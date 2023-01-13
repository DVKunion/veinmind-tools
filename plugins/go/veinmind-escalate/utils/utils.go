package utils

import (
	api "github.com/chaitin/libveinmind/go"

	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-escalate/pkg"
)

func ImagesScanRun(fs api.Image) error {
	for _, check := range pkg.ImageCheckList {
		check(fs)
	}
	return pkg.GenerateImageRoport(fs)

}

func ContainersScanRun(fs api.Container) error {
	for _, check := range pkg.ContainerCheckList {
		check(fs)
	}
	return pkg.GenerateContainerRoport(fs)
}
