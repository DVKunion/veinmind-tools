module github.com/chaitin/veinmind-tools/plugins/go/veinmind-escalate

go 1.16

require (
	github.com/chaitin/libveinmind v1.5.2
	github.com/chaitin/veinmind-common-go v1.4.1
)

require github.com/pelletier/go-toml v1.9.4

replace google.golang.org/grpc/naming => github.com/xiegeo/grpc-naming v1.29.1-alpha
