package main

import (
	"os"
	"time"

	api "github.com/chaitin/libveinmind/go"
	"github.com/chaitin/libveinmind/go/cmd"
	"github.com/chaitin/libveinmind/go/plugin"
	"github.com/chaitin/libveinmind/go/plugin/log"
	"github.com/chaitin/veinmind-common-go/service/report"
	"github.com/chaitin/veinmind-common-go/service/report/event"

	scanner "github.com/chaitin/veinmind-tools/plugins/go/veinmind-vuln/analyzer"
	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-vuln/model"
)

var (
	reportService = &report.Service{}
	results       = []model.ScanResult{}
	scanStart     = time.Now()
	rootCmd       = &cmd.Command{}

	scanCmd = &cmd.Command{
		Use:   "scan",
		Short: "Scan asset and vulns",
	}

	scanImageCmd = &cmd.Command{
		Use:   "image",
		Short: "Scan image asset/vulns",
	}

	scanContainerCmd = &cmd.Command{
		Use:   "container",
		Short: "Scan container asset/vulns",
	}
)

func scanImage(c *cmd.Command, image api.Image) error {
	defer func() {
		err := image.Close()
		if err != nil {
			log.Error(err)
		}
	}()

	threads, _ := c.Flags().GetInt64("threads")
	onlyAsset, _ := c.Flags().GetBool("only-asset")
	verbose, _ := c.Flags().GetBool("verbose")
	res, err := scanner.ScanImage(image, threads)
	if err != nil {
		log.Error("Scan Image Error")
		return err
	}
	// cve
	if !onlyAsset {
		scanner.ScanOSV(&res, verbose)
	}
	// first format, then add
	results = append(results, res)

	if onlyAsset {
		reportEvent := event.Event{
			&event.BasicInfo{
				ID:         image.ID(),
				Object:     event.Object{Raw: image},
				Time:       time.Now(),
				Level:      event.None,
				DetectType: event.Image,
				EventType:  event.Info,
				AlertType:  event.Asset,
			},
			&event.DetailInfo{
				AlertDetail: scanner.TransferAsset(res),
			},
		}
		err = reportService.Client.Report(&reportEvent)
		if err != nil {
			return err
		}
	}

	if res.CveTotal > 0 {
		for _, pkgInfo := range res.PackageInfos {
			for _, pkg := range pkgInfo.Packages {
				for _, vuln := range pkg.Vulnerabilities {

					references := make([]event.References, 0)
					for _, value := range vuln.References {
						tmp := event.References{
							Type: value.Type,
							URL:  value.URL,
						}
						references = append(references, tmp)
					}
					reportEvent := event.Event{
						&event.BasicInfo{
							ID:         image.ID(),
							Object:     event.NewObject(image),
							Time:       time.Now(),
							Level:      event.High,
							DetectType: event.Image,
							EventType:  event.Risk,
							AlertType:  event.Vulnerability,
						},
						event.NewDetailInfo(&event.VulnDetail{
							ID:         vuln.ID,
							Published:  vuln.Published,
							Aliases:    vuln.GetAliases(),
							Summary:    vuln.Summary,
							Details:    vuln.Details,
							References: references,
							Source: event.Source{
								OS:       event.AssetOSDetail(*res.OSInfo),
								Type:     "os-pkg",
								FilePath: pkg.FilePath,
								Packages: event.AssetPackageDetail{
									Name:            pkg.Name,
									Version:         pkg.Version,
									Release:         pkg.Release,
									Epoch:           pkg.Epoch,
									Arch:            pkg.Arch,
									SrcName:         pkg.SrcName,
									SrcVersion:      pkg.SrcVersion,
									SrcRelease:      pkg.SrcRelease,
									SrcEpoch:        pkg.SrcEpoch,
									Modularitylabel: pkg.Modularitylabel,
									Indirect:        pkg.Indirect,
									License:         pkg.License,
									Layer:           pkg.Layer.Digest,
								},
							},
						}),
					}

					err := reportService.Client.Report(&reportEvent)
					if err != nil {
						log.Error(err)
						continue
					}
				}
			}
		}
		for _, appInfo := range res.Applications {
			for _, app := range appInfo.Libraries {
				for _, vuln := range app.Vulnerabilities {

					references := make([]event.References, 0)
					for _, value := range vuln.References {
						tmp := event.References{
							Type: value.Type,
							URL:  value.URL,
						}
						references = append(references, tmp)
					}
					reportEvent := event.Event{
						&event.BasicInfo{
							ID:         image.ID(),
							Object:     event.NewObject(image),
							Time:       time.Now(),
							Level:      event.High,
							DetectType: event.Image,
							EventType:  event.Risk,
							AlertType:  event.Vulnerability,
						},
						event.NewDetailInfo(&event.VulnDetail{
							ID:         vuln.ID,
							Published:  vuln.Published,
							Aliases:    vuln.GetAliases(),
							Summary:    vuln.Summary,
							Details:    vuln.Details,
							References: references,
							Source: event.Source{
								OS:       event.AssetOSDetail(*res.OSInfo),
								Type:     appInfo.Type,
								FilePath: app.FilePath,
								Packages: event.AssetPackageDetail{
									Name:            app.Name,
									Version:         app.Version,
									Release:         app.Release,
									Epoch:           app.Epoch,
									Arch:            app.Arch,
									SrcName:         app.SrcName,
									SrcVersion:      app.SrcVersion,
									SrcRelease:      app.SrcRelease,
									SrcEpoch:        app.SrcEpoch,
									Modularitylabel: app.Modularitylabel,
									Indirect:        app.Indirect,
									License:         app.License,
									Layer:           app.Layer.Digest,
								},
							},
						}),
					}

					err := reportService.Client.Report(&reportEvent)
					if err != nil {
						log.Error(err)
						continue
					}
				}
			}
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

	threads, _ := c.Flags().GetInt64("threads")
	onlyAsset, _ := c.Flags().GetBool("only-asset")
	verbose, _ := c.Flags().GetBool("verbose")
	res, err := scanner.ScanContainer(container, threads)
	if err != nil {
		log.Error("Scan Image Error")
		return err
	}

	if !onlyAsset {
		scanner.ScanOSV(&res, verbose)
	}
	// first format, then add
	results = append(results, res)

	if onlyAsset {
		reportEvent := event.Event{
			&event.BasicInfo{
				ID:         container.ID(),
				Object:     event.Object{Raw: container},
				Time:       time.Now(),
				Level:      event.None,
				DetectType: event.Image,
				EventType:  event.Info,
				AlertType:  event.Asset,
			},
			&event.DetailInfo{
				AlertDetail: scanner.TransferAsset(res),
			},
		}
		err = reportService.Client.Report(&reportEvent)
		if err != nil {
			return err
		}
	}

	if res.CveTotal > 0 {
		for _, pkgInfo := range res.PackageInfos {
			for _, pkg := range pkgInfo.Packages {
				for _, vuln := range pkg.Vulnerabilities {
					references := make([]event.References, 0)
					for _, value := range vuln.References {
						tmp := event.References{
							Type: value.Type,
							URL:  value.URL,
						}
						references = append(references, tmp)
					}
					reportEvent := event.Event{
						&event.BasicInfo{
							ID:         container.ID(),
							Object:     event.NewObject(container),
							Time:       time.Now(),
							Level:      event.High,
							DetectType: event.Image,
							EventType:  event.Risk,
							AlertType:  event.Vulnerability,
						},
						event.NewDetailInfo(&event.VulnDetail{
							ID:         vuln.ID,
							Published:  vuln.Published,
							Aliases:    vuln.GetAliases(),
							Summary:    vuln.Summary,
							Details:    vuln.Details,
							References: references,
							Source: event.Source{
								OS:       event.AssetOSDetail(*res.OSInfo),
								Type:     "os-pkg",
								FilePath: pkg.FilePath,
								Packages: event.AssetPackageDetail{
									Name:            pkg.Name,
									Version:         pkg.Version,
									Release:         pkg.Release,
									Epoch:           pkg.Epoch,
									Arch:            pkg.Arch,
									SrcName:         pkg.SrcName,
									SrcVersion:      pkg.SrcVersion,
									SrcRelease:      pkg.SrcRelease,
									SrcEpoch:        pkg.SrcEpoch,
									Modularitylabel: pkg.Modularitylabel,
									Indirect:        pkg.Indirect,
									License:         pkg.License,
									Layer:           pkg.Layer.Digest,
								},
							},
						}),
					}
					err := reportService.Client.Report(&reportEvent)
					if err != nil {
						log.Error(err)
						continue
					}
				}
			}
		}
		for _, appInfo := range res.Applications {
			for _, app := range appInfo.Libraries {
				for _, vuln := range app.Vulnerabilities {

					references := make([]event.References, 0)
					for _, value := range vuln.References {
						tmp := event.References{
							Type: value.Type,
							URL:  value.URL,
						}
						references = append(references, tmp)
					}
					reportEvent := event.Event{
						&event.BasicInfo{
							ID:         container.ID(),
							Object:     event.NewObject(container),
							Time:       time.Now(),
							Level:      event.High,
							DetectType: event.Image,
							EventType:  event.Risk,
							AlertType:  event.Vulnerability,
						},
						event.NewDetailInfo(&event.VulnDetail{
							ID:         vuln.ID,
							Published:  vuln.Published,
							Aliases:    vuln.GetAliases(),
							Summary:    vuln.Summary,
							Details:    vuln.Details,
							References: references,
							Source: event.Source{
								OS:       event.AssetOSDetail(*res.OSInfo),
								Type:     appInfo.Type,
								FilePath: app.FilePath,
								Packages: event.AssetPackageDetail{
									Name:            app.Name,
									Version:         app.Version,
									Release:         app.Release,
									Epoch:           app.Epoch,
									Arch:            app.Arch,
									SrcName:         app.SrcName,
									SrcVersion:      app.SrcVersion,
									SrcRelease:      app.SrcRelease,
									SrcEpoch:        app.SrcEpoch,
									Modularitylabel: app.Modularitylabel,
									Indirect:        app.Indirect,
									License:         app.License,
									Layer:           app.Layer.Digest,
								},
							},
						}),
					}

					err := reportService.Client.Report(&reportEvent)
					if err != nil {
						log.Error(err)
						continue
					}
				}
			}
		}
	}

	return nil
}

func init() {
	if _, err := os.Open("./data"); os.IsNotExist(err) {
		_ = os.Mkdir("./data", 0600)
	}
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(report.MapReportCmd(cmd.MapImageCommand(scanImageCmd, scanImage), reportService))
	scanCmd.AddCommand(report.MapReportCmd(cmd.MapContainerCommand(scanContainerCmd, scanContainer), reportService))

	rootCmd.AddCommand(cmd.NewInfoCommand(plugin.Manifest{
		Name:        "veinmind-vuln",
		Author:      "veinmind-team",
		Description: "veinmind-vuln scanner image os/pkg/app info and vulns",
	}))
	scanCmd.PersistentFlags().Int64P("threads", "t", 5, "scan file threads")
	scanCmd.PersistentFlags().String("type", "all", "show specify type detail Info")
	scanCmd.PersistentFlags().Bool("only-asset", false, "only scan asset info")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
