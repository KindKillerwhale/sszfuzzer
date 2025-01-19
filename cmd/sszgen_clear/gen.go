// ssz: Go Simple Serialize (SSZ) codec library
// Copyright 2024 ssz Authors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"go/types"
	"sort"
	"strings"
	"text/template"
)

const (
	sszPkgPath = "github.com/karalabe/ssz"
)

type genContext struct {
	pkg     *types.Package
	imports map[string]string
}

func newGenContext(pkg *types.Package) *genContext {
	return &genContext{
		pkg:     pkg,
		imports: make(map[string]string),
	}
}

func (ctx *genContext) addImport(path string, alias string) error {
	if path == ctx.pkg.Path() {
		return nil
	}
	if n, ok := ctx.imports[path]; ok && n != alias {
		return fmt.Errorf("conflict import %s(alias: %s-%s)", path, n, alias)
	}
	ctx.imports[path] = alias
	return nil
}

func (ctx *genContext) header() []byte {
	var paths sort.StringSlice
	for path := range ctx.imports {
		paths = append(paths, path)
	}
	sort.Sort(paths)

	var b bytes.Buffer
	fmt.Fprintf(&b, "package %s\n", ctx.pkg.Name())
	if len(paths) == 0 {
		return b.Bytes()
	}
	if len(paths) == 1 {
		alias := ctx.imports[paths[0]]
		if alias == "" {
			fmt.Fprintf(&b, "import \"%s\"\n", paths[0])
		} else {
			fmt.Fprintf(&b, "import %s \"%s\"\n", alias, paths[0])
		}
		return b.Bytes()
	}
	fmt.Fprintf(&b, "import (\n")
	for _, path := range paths {
		alias := ctx.imports[path]
		if alias == "" {
			fmt.Fprintf(&b, "\"%s\"\n", path)
		} else {
			fmt.Fprintf(&b, "%s \"%s\"\n", alias, path)
		}
	}
	//fmt.Fprintf(&b, ")\n")
	return b.Bytes()
}

func generate(ctx *genContext, typ *sszContainer) ([]byte, error) {
	var codes [][]byte
	for _, fn := range []func(ctx *genContext, typ *sszContainer) ([]byte, error){
		generateClearSSZ,
	} {
		code, err := fn(ctx, typ)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	//fmt.Println(string(bytes.Join(codes, []byte("\n"))))
	return bytes.Join(codes, []byte("\n")), nil
}

func generateClearSSZ(ctx *genContext, typ *sszContainer) ([]byte, error) {

	var b bytes.Buffer

	structName := typ.named.Obj().Name()

	// functino signature
	fmt.Fprintf(&b, "// ClearSSZ zeroes out all fields of %s for leftover decode.\n", structName)
	fmt.Fprintf(&b, "func (obj *%s) ClearSSZ() {\n", structName)

	// For each field, retrieve the `clearStmt` from the opset, expand template placeholders, and handle forks
	for i := 0; i < len(typ.fields); i++ {
		fieldName := typ.fields[i]
		op := typ.opsets[i]

		switch ops := op.(type) {
		case *opsetStatic:
			stmt := parseClearCall(ops.clearStmt, fieldName, ops.bytes)
			fmt.Fprintf(&b, "\t%s\n", stmt)
		case *opsetDynamic:
			stmt := parseClearCall(ops.clearStmt, fieldName, nil)
			fmt.Fprintf(&b, "\t%s\n", stmt)
		}
	}

	fmt.Fprintf(&b, "}\n")
	return b.Bytes(), nil
}

func parseClearCall(tmplStr, fieldName string, size []int) string {
	if tmplStr == "" {
		// fallback
		return fmt.Sprintf("obj.%s = nil // no clearStmt provided", fieldName)
	}

	t, err := template.New("").Parse(tmplStr)
	if err != nil {
		panic(fmt.Errorf("parseClearCall template error: %w", err))
	}

	switch len(size) {
	case 0:

	case 1:
		data := map[string]interface{}{
			"Field": fieldName,
			"Size":  size[0],
		}

		var buf bytes.Buffer
		if err := t.Execute(&buf, data); err != nil {
			panic(fmt.Errorf("parseClearCall exec error: %w", err))
		}
		stmt := buf.String()

		stmt = strings.ReplaceAll(stmt, "o.", "obj.")
		return stmt

	case 2:
		outerSize := size[0]
		innerSize := size[1]

		stmt := tmplStr

		if strings.Contains(stmt, "outerSize") {
			stmt = strings.ReplaceAll(stmt, "outerSize", fmt.Sprintf("%d", outerSize))
		}
		if strings.Contains(stmt, "innerSize") {
			stmt = strings.ReplaceAll(stmt, "innerSize", fmt.Sprintf("%d", innerSize))
		}

		stmt = strings.ReplaceAll(stmt, "{{.Field}}", fieldName)
		stmt = strings.ReplaceAll(stmt, "o.", "obj.")

		return stmt

	default:
		panic(fmt.Errorf("parseClearCall size error: %v", size))
	}

	var buf bytes.Buffer

	data := map[string]interface{}{
		"Field": fieldName,
	}

	if err := t.Execute(&buf, data); err != nil {
		panic(fmt.Errorf("parseClearCall exec error: %w", err))
	}
	stmt := buf.String()

	stmt = strings.ReplaceAll(stmt, "o.", "obj.")

	return stmt
}
