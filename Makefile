build:
	docker build -t tmp -f Dockerfile.mike .
	for i in payloads/payload-*.json; do \
		printf "\n==== Testing $$i ====\n"; \
		docker run -i tmp /opt/resource/check < $$i ; \
	done
