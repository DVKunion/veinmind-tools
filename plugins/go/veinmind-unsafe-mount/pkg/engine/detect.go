package engine

import (
	"github.com/chaitin/veinmind-common-go/service/report/event"
	"path/filepath"
	"time"

	api "github.com/chaitin/libveinmind/go"
	selfreport "github.com/chaitin/veinmind-tools/plugins/go/veinmind-unsafe-mount/pkg/report"
)

func DetectContainerUnsafeMount(container api.Container) (events []event.Event, err error) {
	spec, err := container.OCISpec()
	if err != nil {
		return nil, err
	}

	for _, mount := range spec.Mounts {
		for _, pattern := range UnsafeMountPaths {
			matched, err := filepath.Match(pattern, mount.Source)
			if err != nil {
				continue
			}

			if matched {
				if err != nil {
					continue
				}
				events = append(events, event.Event{
					&event.BasicInfo{
						ID:         container.ID(),
						Object:     event.Object{Raw: container},
						Time:       time.Now(),
						Level:      event.High,
						DetectType: event.Container,
						EventType:  event.Risk,
						AlertType:  "UnsafeMount",
					},
					event.NewDetailInfo(&selfreport.UnSafeMountDetail{
						selfreport.MountEvent{
							Source:      mount.Source,
							Destination: mount.Destination,
							Type:        mount.Type,
						},
					}),
				})
			}
		}
	}
	return
}
func init() {

}
