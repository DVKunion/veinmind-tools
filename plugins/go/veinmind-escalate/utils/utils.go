package utils

import (
	api "github.com/chaitin/libveinmind/go"
	"github.com/chaitin/libveinmind/go/plugin/log"

	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-escalate/pkg"
)

func ImagesScanRun(fs api.Image) {
	for _, check := range pkg.ImageCheckList {
		err := check(fs)
		if err != nil {
			log.Warning(err)
			continue
		}
	}
}

func ContainersScanRun(fs api.Container) {
	for _, check := range pkg.ContainerCheckList {
		err := check(fs)
		if err != nil {
			log.Warning(err)
			continue
		}
	}
}
