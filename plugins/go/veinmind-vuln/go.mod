module github.com/chaitin/veinmind-tools/plugins/go/veinmind-vuln

go 1.16

require (
	github.com/aquasecurity/go-dep-parser v0.0.0-20220904090510-d2cb7a409fe8
	github.com/aquasecurity/trivy v0.29.2
	github.com/chaitin/libveinmind v1.5.2
	github.com/chaitin/veinmind-common-go v1.4.2
	golang.org/x/sync v0.1.0
)

require (
	cloud.google.com/go/iam v0.9.0 // indirect
	github.com/aquasecurity/defsec v0.82.0 // indirect
	github.com/aws/aws-sdk-go v1.44.136 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/knqyf263/go-rpmdb v0.0.0-20221030142135-919c8a52f04f // indirect
	github.com/samber/lo v1.33.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.23.0 // indirect
	golang.org/x/exp v0.0.0-20220823124025-807a23277127 // indirect
	golang.org/x/tools v0.2.0 // indirect
	k8s.io/cli-runtime v0.25.3 // indirect
)

replace (
	// containerd main
	github.com/containerd/containerd => github.com/containerd/containerd v1.6.1-0.20220606171923-c1bcabb45419
	// See https://github.com/moby/moby/issues/42939#issuecomment-1114255529
	github.com/docker/docker => github.com/docker/docker v20.10.3-0.20220224222438-c78f6963a1c0+incompatible
)
