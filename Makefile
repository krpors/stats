all:
	go get github.com/crazy2be/ini
	go install github.com/krpors/stats

clean:
	go clean -i github.com/krpors/stats

run-test:
	$(GOPATH)/bin/stats
