package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cihub/seelog"
	"github.com/pivotal-golang/lager"

	"github.com/Masterminds/semver"
	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	ecrapi "github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/concourse/retryhttp"
	"github.com/docker/distribution"
	"github.com/docker/distribution/digest"
	_ "github.com/docker/distribution/manifest/schema1"
	_ "github.com/docker/distribution/manifest/schema2"
	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/hashicorp/go-multierror"
	"github.com/pivotal-golang/clock"
)

func main() {
	logger := lager.NewLogger("http")

	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.DEBUG))

	var request CheckRequest
	err := json.NewDecoder(os.Stdin).Decode(&request)
	fatalIf("failed to read request", err)

	os.Setenv("AWS_ACCESS_KEY_ID", request.Source.AWSAccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", request.Source.AWSSecretAccessKey)

	// silence benign ecr-login errors/warnings
	seelog.UseLogger(seelog.Disabled)

	ecrUser, ecrPass, err := ecr.ECRHelper{
		ClientFactory: ecrapi.DefaultClientFactory{},
	}.Get(request.Source.Repository)
	if err == nil {
		request.Source.Username = ecrUser
		request.Source.Password = ecrPass
	}

	registryHost, repo := parseRepository(request.Source.Repository)

	if len(request.Source.RegistryMirror) > 0 {
		registryMirrorUrl, err := url.Parse(request.Source.RegistryMirror)
		fatalIf("failed to parse registry mirror URL", err)
		registryHost = registryMirrorUrl.Host
	}

	transport, registryURL := makeTransport(logger, request, registryHost, repo)

	namedRef, err := reference.WithName(repo)
	fatalIf("failed to construct named reference", err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	repository, err := client.NewRepository(ctx, namedRef, registryURL, retryRoundTripper(logger, transport))
	fatalIf("failed to construct repository", err)

	if request.Source.TagFilter != "" {
		response := fetchTags(ctx, repository, request.Version, request.Source.TagFilter)
		json.NewEncoder(os.Stdout).Encode(response)
	} else {
		tag := request.Source.Tag.String()
		if tag == "" {
			tag = "latest"
		}
		response := fetchTag(ctx, repository, request.Version, tag)
		json.NewEncoder(os.Stdout).Encode(response)
	}

}

func fetchTags(ctx context.Context, repo distribution.Repository, cursor Version, tagFilter string) CheckResponse {
	var response CheckResponse
	tagManager := repo.Tags(ctx)

	tags, err := tagManager.All(ctx)
	fatalIf("failed to retrieve tags", err)

	var matchedTags []semver.Version

	for _, tag := range tags {
		matched, err := filepath.Match(tagFilter, tag)
		fatalIf("failed to parse tag_filter", err)
		if matched {
			v, err := semver.NewVersion(tag)
			fatalIf("failed to parse "+tag+" as semver", err)
			matchedTags = append(matchedTags, v)
		}
	}

	if len(matchedTags) == 0 {
		return nil
	}

	// Newest is now first (note: concourse wants newest _last_ so beware)
	sort.Sort(sort.Reverse(semver.Collection(matchedTags)))

	// if we don't have a cursor, don't pull the entire history, just the
	// newest, since that could be a lot (this matches the git-resource
	// behavior); we'll copy from this index backwards to 0, inclusive, so this
	// default means "take the newest only"
	fromHere := 0
	if cursor.Tag != "" {
		for idx, ver := range matchedTags {
			if ver.Original() == cursor.Tag {
				fromHere = idx
				break
			}
		}
	}

	// We iterate backwards intentionally to make sure the newest tag ends up
	// last, the way concourse expects
	for idx := fromHere; idx >= 0; idx-- {
		tag := matchedTags[idx].Original()
		descriptor, err := tagManager.Get(ctx, tag)
		// No 404 check here because we won't tolerate failure.
		fatalIf("failed to retrieve tag "+tag+" from repo", err)

		response = append(response, Version{
			Tag:    tag,
			Digest: descriptor.Digest.String(),
		})
	}

	return response
}

func fetchTag(ctx context.Context, repo distribution.Repository, cursor Version, tag string) CheckResponse {
	var response CheckResponse

	tagManager := repo.Tags(ctx)

	descriptor, err := tagManager.Get(ctx, tag)
	foundLatest, err := isFound(err)
	fatalIf("failed to retrieve tag from repo", err)

	latestDigest := descriptor.Digest

	if cursor.Digest != "" {
		cursorDigest, err := digest.ParseDigest(cursor.Digest)
		fatalIf("failed to parse cursor digest", err)

		manifestManager, err := repo.Manifests(ctx, client.ReturnContentDigest(&cursorDigest))
		fatalIf("failed to make manifest service", err)

		foundCursor, err := manifestManager.Exists(ctx, cursorDigest)
		fatalIf("failed to check if cursor exists", err)

		if foundCursor && cursorDigest != latestDigest {
			response = append(response, Version{Digest: cursorDigest.String()})
		}
	}

	if foundLatest {
		response = append(response, Version{Digest: latestDigest.String()})
	}
	return response
}

func makeTransport(logger lager.Logger, request CheckRequest, registryHost string, repository string) (http.RoundTripper, string) {
	// for non self-signed registries, caCertPool must be nil in order to use the system certs
	var caCertPool *x509.CertPool
	if len(request.Source.DomainCerts) > 0 {
		caCertPool = x509.NewCertPool()
		for _, domainCert := range request.Source.DomainCerts {
			ok := caCertPool.AppendCertsFromPEM([]byte(domainCert.Cert))
			if !ok {
				fatal(fmt.Sprintf("failed to parse CA certificate for \"%s\"", domainCert.Domain))
			}
		}
	}

	baseTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: caCertPool},
	}

	var insecure bool
	for _, hostOrCIDR := range request.Source.InsecureRegistries {
		if isInsecure(hostOrCIDR, registryHost) {
			insecure = true
		}
	}

	if insecure {
		baseTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	if len(request.Source.ClientCerts) > 0 {
		baseTransport.TLSClientConfig = &tls.Config{
			RootCAs:      caCertPool,
			Certificates: setClientCert(registryHost, request.Source.ClientCerts),
		}
	}

	authTransport := transport.NewTransport(baseTransport)

	pingClient := &http.Client{
		Transport: retryRoundTripper(logger, authTransport),
		Timeout:   1 * time.Minute,
	}

	challengeManager := challenge.NewSimpleManager()

	var registryURL string

	var pingResp *http.Response
	var pingErr error
	var pingErrs error
	for _, scheme := range []string{"https", "http"} {
		registryURL = scheme + "://" + registryHost

		req, err := http.NewRequest("GET", registryURL+"/v2/", nil)
		fatalIf("failed to create ping request", err)

		pingResp, pingErr = pingClient.Do(req)
		if pingErr == nil {
			// clear out previous attempts' failures
			pingErrs = nil
			break
		}

		pingErrs = multierror.Append(
			pingErrs,
			fmt.Errorf("ping %s: %s", scheme, pingErr),
		)
	}
	fatalIf("failed to ping registry", pingErrs)

	defer pingResp.Body.Close()

	err := challengeManager.AddResponse(pingResp)
	fatalIf("failed to add response to challenge manager", err)

	credentialStore := dumbCredentialStore{request.Source.Username, request.Source.Password}
	tokenHandler := auth.NewTokenHandler(authTransport, credentialStore, repository, "pull")
	basicHandler := auth.NewBasicHandler(credentialStore)
	authorizer := auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler)

	return transport.NewTransport(baseTransport, authorizer), registryURL
}

type dumbCredentialStore struct {
	username string
	password string
}

func (dcs dumbCredentialStore) Basic(*url.URL) (string, string) {
	return dcs.username, dcs.password
}

func (dumbCredentialStore) RefreshToken(u *url.URL, service string) string {
	return ""
}

func (dumbCredentialStore) SetRefreshToken(u *url.URL, service, token string) {
}

func fatalIf(doing string, err error) {
	if err != nil {
		fatal(doing + ": " + err.Error())
	}
}

func fatal(message string) {
	println(message)
	os.Exit(1)
}

const officialRegistry = "registry-1.docker.io"

func parseRepository(repository string) (string, string) {
	segs := strings.Split(repository, "/")

	if len(segs) > 1 && (strings.Contains(segs[0], ":") || strings.Contains(segs[0], ".")) {
		// In a private regsitry pretty much anything is valid.
		return segs[0], strings.Join(segs[1:], "/")
	}
	switch len(segs) {
	case 3:
		return segs[0], segs[1] + "/" + segs[2]
	case 2:
		return officialRegistry, segs[0] + "/" + segs[1]
	case 1:
		return officialRegistry, "library/" + segs[0]
	}

	fatal("malformed repository url")
	panic("unreachable")
}

func isInsecure(hostOrCIDR string, hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostOrCIDR == hostPort
	}

	_, cidr, err := net.ParseCIDR(hostOrCIDR)
	if err == nil {
		ip := net.ParseIP(host)
		if ip != nil {
			return cidr.Contains(ip)
		}
	}

	return hostOrCIDR == hostPort
}

func retryRoundTripper(logger lager.Logger, rt http.RoundTripper) http.RoundTripper {
	return &retryhttp.RetryRoundTripper{
		Logger:  logger,
		Sleeper: clock.NewClock(),
		RetryPolicy: retryhttp.ExponentialRetryPolicy{
			Timeout: 5 * time.Minute,
		},
		RoundTripper: rt,
	}
}

func setClientCert(registry string, list []ClientCertKey) []tls.Certificate {
	var clientCert []tls.Certificate
	for _, r := range list {
		if r.Domain == registry {
			certKey, err := tls.X509KeyPair([]byte(r.Cert), []byte(r.Key))
			if err != nil {
				fatal(fmt.Sprintf("failed to parse client certificate and/or key for \"%s\"", r.Domain))
			}
			clientCert = append(clientCert, certKey)
		}
	}
	return clientCert
}

func isFound(err error) (bool, error) {
	// 404s aren't fatal, but docker doesn't give us a great way to detect
	// them...
	if err == nil {
		return true, nil
	} else if strings.Contains(err.Error(), "manifest unknown") {
		return false, nil
	} else {
		return false, err
	}
}
