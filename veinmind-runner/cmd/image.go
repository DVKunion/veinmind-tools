package main

import (
	"context"
	"github.com/chaitin/libveinmind/go/cmd"
	"github.com/chaitin/libveinmind/go/containerd"
	"github.com/chaitin/libveinmind/go/docker"
	"github.com/chaitin/libveinmind/go/plugin"
	"github.com/chaitin/libveinmind/go/plugin/log"
	"github.com/chaitin/libveinmind/go/plugin/service"
	"path"
	"regexp"
	"sync"
)

var scanImageCmd = &cmd.Command{
	Use:      "image",
	Short:    "perform image scan ",
	PreRunE:  scanReportPreRunE,
	RunE:     ScanImage,
	PostRunE: scanReportPostRunE,
}

func ScanImage(c *cmd.Command, args []string) error {
	wg := &sync.WaitGroup{}
	wg.Add(len(args))
	for _, value := range args {
		handler := ScanImageParser(value)
		go func(handler Handler, value string, wg *sync.WaitGroup) {
			defer wg.Done()
			err := handler(c, value)
			if err != nil {
				log.Error(err)
			}
		}(handler, value, wg)
	}
	wg.Wait()
	return nil
}

func ScanImageDocker(c *cmd.Command, arg string) error {
	regex := "docker?:?(.*)"
	compileRegex := regexp.MustCompile(regex)
	matchArr := compileRegex.FindStringSubmatch(arg)
	r, err := docker.New()
	if err != nil {
		return err
	}
	ids, err := r.FindImageIDs(matchArr[1])
	for _, id := range ids {
		image, err := r.OpenImageByID(id)
		refs, err := image.RepoRefs()
		ref := ""
		if err == nil && len(refs) > 0 {
			ref = refs[0]
		} else {
			ref = image.ID()
		}

		// Get threads value
		t, err := c.Flags().GetInt("threads")
		if err != nil {
			t = 5
		}

		log.Infof("Scan image: %#v\n", ref)
		if err := cmd.ScanImage(ctx, ps, image,
			plugin.WithExecInterceptor(func(
				ctx context.Context, plug *plugin.Plugin, c *plugin.Command, next func(context.Context, ...plugin.ExecOption) error,
			) error {
				// Register Service
				reg := service.NewRegistry()
				reg.AddServices(log.WithFields(log.Fields{
					"plugin":  plug.Name,
					"command": path.Join(c.Path...),
				}))
				reg.AddServices(reportService)

				// Next Plugin
				return next(ctx, reg.Bind())
			}), plugin.WithExecParallelism(t)); err != nil {
			return err
		}
		return nil
	}
	return nil
}

func ScanImageContainerd(c *cmd.Command, arg string) error {
	regex := "containerd?:?(.*)"
	compileRegex := regexp.MustCompile(regex)
	matchArr := compileRegex.FindStringSubmatch(arg)
	r, err := containerd.New()
	if err != nil {
		return err
	}
	ids, err := r.FindImageIDs(matchArr[1])
	for _, id := range ids {
		image, err := r.OpenImageByID(id)
		refs, err := image.RepoRefs()
		ref := ""
		if err == nil && len(refs) > 0 {
			ref = refs[0]
		} else {
			ref = image.ID()
		}

		// Get threads value
		t, err := c.Flags().GetInt("threads")
		if err != nil {
			t = 5
		}

		log.Infof("Scan image: %#v\n", ref)
		if err := cmd.ScanImage(ctx, ps, image,
			plugin.WithExecInterceptor(func(
				ctx context.Context, plug *plugin.Plugin, c *plugin.Command, next func(context.Context, ...plugin.ExecOption) error,
			) error {
				// Register Service
				reg := service.NewRegistry()
				reg.AddServices(log.WithFields(log.Fields{
					"plugin":  plug.Name,
					"command": path.Join(c.Path...),
				}))
				reg.AddServices(reportService)

				// Next Plugin
				return next(ctx, reg.Bind())
			}), plugin.WithExecParallelism(t)); err != nil {
			return err
		}
		return nil
	}
	return nil
}

func ScanImageRegistry(c *cmd.Command, arg string) error {
	return nil
}

func ScanImageParser(arg string) Handler {
	regex := "(docker|containerd|tarball|registry):(.*)"
	compileRegex := regexp.MustCompile(regex)
	matchArr := compileRegex.FindStringSubmatch(arg)
	switch matchArr[1] {
	case DOCKER:
		return ScanImageDocker
	case CONTAINERD:
		return ScanImageContainerd
	case REGISTRY:
		return ScanImageRegistry
	default:
		log.Errorf("please input right args, available: docker,containerd,registry")
	}
	return nil
}
