package scanner

import (
	"context"
	"errors"
	api "github.com/chaitin/libveinmind/go/iac"
	"github.com/chaitin/libveinmind/go/kubernetes"
	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-iac/pkg/parser"
	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-iac/rules"
	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Scanner struct {
	QueryPre string
	Policies map[string]*ast.Module
}

func (bs *Scanner) Scan(ctx context.Context, iacFile api.IAC) ([]Result, error) {
	// parseHandle
	parseHandle := parser.NewParser(iacFile)
	if parseHandle == nil {
		return nil, errors.New("un support iac type")
	}

	// load rules
	err := bs.LoadRules(iacFile.Type)
	if err != nil {
		return nil, err
	}

	// open file
	file, err := os.Open(iacFile.Path)
	if err != nil {
		return nil, err
	}

	defer file.Close()
	// parse
	input, err := parseHandle(file, iacFile.Path)
	if err != nil {
		return nil, err
	}
	// prepare
	compiler := ast.NewCompiler()
	compiler.Compile(bs.Policies)
	if compiler.Failed() {
		return nil, compiler.Errors
	}

	// scan
	options := []func(*rego.Rego){
		rego.Query(bs.QueryPre + iacFile.Type.String()),
		rego.Compiler(compiler),
		rego.Input(input),
	}
	res, err := bs.runOPA(ctx, options...)
	if err != nil {
		return nil, err
	}

	// format
	var formatResult []Result

	value, ok := res.Value.(map[string]interface{})
	if !ok {
		return formatResult, errors.New("result format error")
	}
	for _, v := range value["risks"].([]interface{}) {
		var d = struct {
			Risk
			Rule
		}{}
		err := mapstructure.Decode(v, &d)
		if err != nil {
			continue
		}
		formatResult = append(formatResult, Result{
			Risks: []Risk{
				d.Risk,
			},
			Rule: &d.Rule,
		})
	}
	return formatResult, nil
}

func (bs *Scanner) LoadRules(fileType api.IACType) error {
	return bs.load(fileType.String())
}

func (bs *Scanner) LoadLibs() error {
	return bs.load("common")
}

func (bs *Scanner) load(path string) error {
	entries, err := rules.RegoFile.ReadDir(filepath.ToSlash(path))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			bs.load(entry.Name())
		} else {
			absolutePath := strings.Join(append([]string{path}, entry.Name()), "/")
			if _, ok := bs.Policies[absolutePath]; ok {
				// already load
				continue
			}
			data, err := fs.ReadFile(rules.RegoFile, absolutePath)
			if err != nil {
				return err
			}
			module, err := ast.ParseModuleWithOpts(absolutePath, string(data), ast.ParserOptions{})
			if err != nil {
				return err
			}
			bs.Policies[absolutePath] = module
		}
	}
	return nil
}

func (bs *Scanner) runOPA(ctx context.Context, options ...func(r *rego.Rego)) (*rego.ExpressionValue, error) {
	r := rego.New(
		options...,
	)
	// do scanner
	queryResult, err := r.Eval(ctx)

	if err != nil {
		return nil, err
	}
	if len(queryResult) == 0 || len(queryResult[0].Expressions) == 0 {
		return nil, errors.New("扫描结果异常")
	}
	// return
	return queryResult[0].Expressions[0], nil
}

func (bs *Scanner) ScanByConfig(ctx context.Context, configfile string) ([]Result, error) {
	//获取各个pod的annotation数据
	PodConfigs, err := getInput(configfile)
	if err != nil {
		return nil, err
	}
	err = bs.LoadRules("kubernetes")
	if err != nil {
		return nil, err
	}
	compiler := ast.NewCompiler()
	compiler.Compile(bs.Policies)
	if compiler.Failed() {
		return nil, compiler.Errors
	}
	if err != nil {
		return nil, err
	}
	var formatResult []Result
	for i := 0; i < len(PodConfigs); i++ {
		input, err := parser.KubernetesByConfig(PodConfigs[i])
		if err != nil {
			return nil, err
		}
		options := []func(*rego.Rego){
			rego.Query("data.brightMirror.kubernetes"),
			rego.Compiler(compiler),
			rego.Input(input),
		}
		res, err := bs.runOPA(ctx, options...)
		if err != nil {
			continue
		}
		// format
		value, ok := res.Value.(map[string]interface{})
		if !ok {
			continue
		}
		for _, v := range value["risks"].([]interface{}) {
			var d = struct {
				Risk
				Rule
			}{}
			err := mapstructure.Decode(v, &d)
			if err != nil {
				continue
			}
			formatResult = append(formatResult, Result{
				Risks: []Risk{
					d.Risk,
				},
				Rule: &d.Rule,
			})
		}
	}

	return formatResult, nil

}

func getInput(kubeconfig string) ([]string, error) {
	res := make([]string, 0)
	option := kubernetes.WithKubeConfig(kubeconfig)
	myk8s, err := kubernetes.New(option)
	if err != nil {
		return nil, err
	}
	objNamespaces, _ := myk8s.Resource("namespaces")
	namespaces, err := objNamespaces.List(context.TODO())
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(namespaces); i++ {
		optionForNamespace := kubernetes.WithNamespace(namespaces[i])
		myk8s, err := kubernetes.New(option, optionForNamespace)
		if err != nil {
			return nil, err
		}
		objPods, err := myk8s.Resource("pods")
		if err != nil {
			return nil, err
		}
		pods, err := objPods.List(context.TODO())
		if err != nil {
			return nil, err
		}
		for j := 0; j < len(pods); j++ {
			podsConfig, err := objPods.Get(context.TODO(), pods[j])
			if err != nil {
				return nil, err
			}
			tmp := namespaces[i] + "^" + pods[j] + "^" + string(podsConfig) //用^分割namespcaename，podname和pod信息
			res = append(res, tmp)
		}
	}
	return res, nil
}
