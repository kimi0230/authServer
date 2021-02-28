package discover

import (
	"log"
	"strconv"
	"sync"

	"github.com/go-kit/kit/sd/consul"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
)

type KitDiscoverClient struct {
	Host   string // Consul Host
	Port   int    // Consul Port
	client consul.Client
	// 連接 consul 的配置
	config *api.Config
	mutex  sync.Mutex
	// 服務實例緩衝字段. 避免每次獲取服務實例信息都需要和consul發生一次http交互
	instancesMap sync.Map
}

func NewKitDiscoverClient(consulHost string, consulPort int) (DiscoveryClient, error) {
	// 通過 Consul Host 和 Consul Port 建立一個 consul.Client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = consulHost + ":" + strconv.Itoa(consulPort)
	apiClient, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}
	client := consul.NewClient(apiClient)
	return &KitDiscoverClient{
		Host:   consulHost,
		Port:   consulPort,
		config: consulConfig,
		client: client,
	}, err
}

// Register : 服務實例將自身所屬服務名和服務meta data註冊到consul中
func (consulClient *KitDiscoverClient) Register(serviceName, instanceId, healthCheckUrl string, instanceHost string, instancePort int, meta map[string]string, logger *log.Logger) bool {

	// 1. 建立服務實例
	serviceRegistration := &api.AgentServiceRegistration{
		ID:      instanceId,
		Name:    serviceName,
		Address: instanceHost,
		Port:    instancePort,
		Meta:    meta,
		Check: &api.AgentServiceCheck{
			DeregisterCriticalServiceAfter: "30s",
			HTTP:                           "http://" + instanceHost + ":" + strconv.Itoa(instancePort) + healthCheckUrl,
			Interval:                       "15s",
		},
	}

	// 2. 發送服務註冊到Consul
	err := consulClient.client.Register(serviceRegistration)

	if err != nil {
		log.Println("Register Service Error!")
		return false
	}
	log.Println("Register Service Success!")
	return true
}

// DeRegister : 服務關閉時請求 consul 將自身數據消除
func (consulClient *KitDiscoverClient) DeRegister(instanceId string, logger *log.Logger) bool {

	// 建構包煩服務實例 id 的 AgentServiceRegistration結構
	serviceRegistration := &api.AgentServiceRegistration{
		ID: instanceId,
	}
	// 發送服務註銷
	err := consulClient.client.Deregister(serviceRegistration)

	if err != nil {
		logger.Println("Deregister Service Error!")
		return false
	}
	log.Println("Deregister Service Success!")

	return true
}

// DiscoverServices : 通過服務名稱向 consul 請求對應的 instance 信息列表
func (consulClient *KitDiscoverClient) DiscoverServices(serviceName string, logger *log.Logger) []interface{} {

	//  該服務已監控並緩存
	instanceList, ok := consulClient.instancesMap.Load(serviceName)
	if ok {
		return instanceList.([]interface{})
	}

	consulClient.mutex.Lock()
	defer consulClient.mutex.Unlock()
	// 再次檢查是否有此服務
	instanceList, ok = consulClient.instancesMap.Load(serviceName)
	if ok {
		// 該服務已監控並緩存
		return instanceList.([]interface{})
	} else {
		// 註冊監控
		go func() {
			// 使用 consul 服務實例監控來件控否個服務名的服務實例列表變化
			params := make(map[string]interface{})
			params["type"] = "service"
			params["service"] = serviceName
			plan, _ := watch.Parse(params)
			plan.Handler = func(u uint64, i interface{}) {
				if i == nil {
					return
				}
				v, ok := i.([]*api.ServiceEntry)
				if !ok {
					return
				}
				// 沒有服務實例在線上
				if len(v) == 0 {
					consulClient.instancesMap.Store(serviceName, []interface{}{})
				}
				var healthServices []interface{}
				for _, service := range v {
					if service.Checks.AggregatedStatus() == api.HealthPassing {
						healthServices = append(healthServices, service.Service)
					}
				}
				consulClient.instancesMap.Store(serviceName, healthServices)
			}
			defer plan.Stop()
			plan.Run(consulClient.config.Address)
		}()
	}

	// 根據服務名稱請求服務實例列表
	entries, _, err := consulClient.client.Service(serviceName, "", false, nil)
	if err != nil {
		// 出錯 清空該服務名稱的實例列表
		consulClient.instancesMap.Store(serviceName, []interface{}{})
		logger.Println("Discover Service Error!")
		return nil
	}
	// 寫入緩衝
	instances := make([]interface{}, len(entries))
	for i := 0; i < len(instances); i++ {
		instances[i] = entries[i].Service
	}
	consulClient.instancesMap.Store(serviceName, instances)
	return instances
}
