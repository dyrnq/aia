package conf



type Config struct {
	Listen				string				`mapstructure:"listen"`
	ReleaseMode		 	string				`mapstructure:"release-mode"`
	XApiKey		 		string				`mapstructure:"x-api-key"`
	ApisixConfig		string				`mapstructure:"apisix-config"`
	ApisixReloadCmd		string				`mapstructure:"apisix-reload-cmd"`
	ApisixStopCmd		string				`mapstructure:"apisix-stop-cmd"`
	ApisixStartCmd		string				`mapstructure:"apisix-start-cmd"`
	ApisixReStartCmd	string				`mapstructure:"apisix-restart-cmd"`
}
