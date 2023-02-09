package main

import (
	"github.com/chaitin/veinmind-common-go/service/report"
	"github.com/chaitin/veinmind-common-go/service/report/event"
	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-escalate/pkg"
	"os"
	"time"

	api "github.com/chaitin/libveinmind/go"
	"github.com/chaitin/libveinmind/go/cmd"
	"github.com/chaitin/libveinmind/go/plugin"
	"github.com/chaitin/libveinmind/go/plugin/log"

	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-escalate/utils"
)

var ReportService = &report.Service{}

var rootCmd = &cmd.Command{}

var scanCmd = &cmd.Command{
	Use:   "scan",
	Short: "scan mode",
}
var scanImageCmd = &cmd.Command{
	Use:   "image",
	Short: "scan image escalate",
}
var scanContainerCmd = &cmd.Command{
	Use:   "container",
	Short: "scan container escalate",
}

func scanImage(c *cmd.Command, image api.Image) error {
	defer func() {
		err := image.Close()
		if err != nil {
			log.Error(err)
		}
	}()
	utils.ImagesScanRun(image)
	for _, result := range pkg.Result {
		ReportEvent := &event.Event{
			BasicInfo: &event.BasicInfo{
				ID:         image.ID(),
				Time:       time.Now(),
				Level:      event.High,
				Object:     event.NewObject(image),
				EventType:  event.Risk,
				DetectType: event.Image,
				AlertType:  event.Escape,
			},
			DetailInfo: event.NewDetailInfo(&event.EscapeDetail{
				Target: result.Target,
				Reason: result.Reason,
				Detail: result.Detail,
			}),
		}
		err := ReportService.Client.Report(ReportEvent)
		if err != nil {
			log.Error(err)
			continue
		}
	}

	return nil
}

func scanContainer(c *cmd.Command, container api.Container) error {
	defer func() {
		err := container.Close()
		if err != nil {
			log.Error(err)
		}
	}()
	utils.ContainersScanRun(container)
	for _, result := range pkg.Result {
		ReportEvent := &event.Event{
			BasicInfo: &event.BasicInfo{
				ID:         container.ID(),
				Time:       time.Now(),
				Level:      event.High,
				Object:     event.NewObject(container),
				EventType:  event.Risk,
				DetectType: event.Image,
				AlertType:  event.Escape,
			},
			DetailInfo: event.NewDetailInfo(&event.EscapeDetail{
				Target: result.Target,
				Reason: result.Reason,
				Detail: result.Detail,
			}),
		}
		err := ReportService.Client.Report(ReportEvent)
		if err != nil {
			log.Error(err)
			continue
		}
	}

	return nil
}

func init() {

	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(report.MapReportCmd(cmd.MapImageCommand(scanImageCmd, scanImage), ReportService))
	scanCmd.AddCommand(report.MapReportCmd(cmd.MapContainerCommand(scanContainerCmd, scanContainer), ReportService))
	rootCmd.AddCommand(cmd.NewInfoCommand(plugin.Manifest{
		Name:        "veinmind-escalate",
		Author:      "veinmind-team",
		Description: "detect escalation risk for image&container",
	}))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
