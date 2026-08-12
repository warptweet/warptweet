//go:build !linux && !darwin

package engine

import "errors"

func productionClientAssetDependencies() (clientAssetDependencies, error) {
	return clientAssetDependencies{}, errors.New("production client-state validation requires Linux or Darwin")
}

func productionClientStateLayout() clientStateLayout {
	return linuxProductionClientStateLayout()
}
