.PHONY: build test test-recovery bundle clean

build:
	python3 scripts/notices.py
	python3 scripts/icons.py
	npm run build
	touch internal/web/dist/.gitkeep
	mkdir -p bin
	go build -trimpath -o bin/shellport ./cmd/shellport

test:
	python3 -B -m unittest discover -s scripts -p '*_test.py'
	npm run typecheck
	npm test
	go test -race ./...
	go vet ./...

# Included in make test too; the explicit target reruns only this rehearsal.
test-recovery:
	go test -race ./internal/shellport -run '^TestUpgradeBackupRecovery$$' -count=1 -v

bundle: build
	mkdir -p bundle/linux-arm64 bundle/linux-armv7
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bundle/linux-arm64/shellport ./cmd/shellport
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -o bundle/linux-armv7/shellport ./cmd/shellport

clean:
	rm -rf bin bundle
