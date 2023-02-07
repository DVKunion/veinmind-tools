module github.com/chaitin/veinmind-tools/plugins/go/veinmind-webshell

go 1.16

require (
	github.com/chaitin/libveinmind v1.5.2
	github.com/chaitin/veinmind-common-go v1.4.1
	github.com/magiconair/properties v1.8.5
	golang.org/x/sync v0.1.0
)

replace google.golang.org/grpc/naming => github.com/xiegeo/grpc-naming v1.29.1-alpha
