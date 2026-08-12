//go:build linux

package engine

func productionExecutableInspector() executableInspector {
	return elfExecutableInspector{}
}
