//go:build darwin

package engine

func productionExecutableInspector() executableInspector {
	return machoExecutableInspector{}
}
