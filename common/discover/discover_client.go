package discover

import (
	"log"
)

type DiscoveryClient interface {
	/**
	 * 服務註冊接口
	 * @param serviceName 服務名稱
	 * @param instanceId 服務實例 id
	 * @param instancePort 服務 port
	 * @param healthCheckUrl 健康檢查 URL
	 * @param instanceHost 服務器 Host address
	 * @param meta 服務實例 meta data
	 */
	Register(serviceName, instanceId, healthCheckUrl string, instanceHost string, instancePort int, meta map[string]string, logger *log.Logger) bool

	/**
	 * 註銷服務接口
	 * @param instanceId 服務實例 id
	 */
	DeRegister(instanceId string, logger *log.Logger) bool

	/**
	 * 發現服務實例接口
	 * @param serviceName 服務名稱
	 */
	DiscoverServices(serviceName string, logger *log.Logger) []interface{}
}
