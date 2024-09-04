package main
import (
    "log"
    "net"
    "net/http"
    "os/exec"
    "bytes"
    "github.com/gin-gonic/gin"
    "github.com/spf13/pflag"
    "github.com/spf13/viper"
    "regexp"
    "github.com/dyrnq/aia/conf"
    "encoding/base64"
    "io/ioutil"
    "os"
    "strings"
    "fmt"
    "sigs.k8s.io/yaml"
)

var (
    version   = "development" // 默认值
    commit    = ""            // Git 提交哈希
    buildDate = ""            // 构建日期
)


// Middleware 用于验证 API 密钥
func apiKeyMiddleware(param string) gin.HandlerFunc {
    return func(c *gin.Context) {
        apiKey := c.GetHeader("X-API-KEY")
        if apiKey != param {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
            c.Abort() // 终止请求
            return
        }
        c.Next() // 继续处理请求
    }
}

// IPWhitelistMiddleware 创建一个中间件来检查 IP 白名单
func IPWhitelistMiddleware(allowedIPs []string) gin.HandlerFunc {
    return func(c *gin.Context) {
        clientIP := c.ClientIP()

        // 检查 IP 是否在允许的列表中
        for _, ip := range allowedIPs {
            if ip == clientIP || checkIPRange(ip, clientIP) {
                c.Next() // 允许访问
                return
            }
        }

        // 拒绝访问
        c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
        c.Abort()
    }
}

// checkIPRange 检查给定的 IP 是否在范围内
func checkIPRange(cidr string, ip string) bool {
    _, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return false
    }
    return ipnet.Contains(net.ParseIP(ip))
}

// 定义一个结构体，用于接收 JSON 数据
type PostConfig struct {
    Data string `json:"data" binding:"required"`
}

// escapeBashSpecialChars 转义 Bash 中的特殊字符
func escapeBashSpecialChars(input string) string {
    // 定义需要转义的特殊字符及其转义形式
    specialChars := map[string]string{
        `$`:  `\$`,
        `#`:  `\#`,
        `&`:  `\&`,
        `*`:  `\*`,
        `?`:  `\?`,
        `;`:  `\;`,
        `|`:  `\|`,
        `>`:  `\>`,
        `<`:  `\<`,
        `(`:  `\(`,
        `)`:  `\)`,
        `{`:  `\{`,
        `}`:  `\}`,
        `[`:  `\[` ,
        `]`:  `\]`,
        `'`:  `\'`,
        `"`:  `\"`,
        `\`:  `\\`,
        `!`:  `\!`,
        `~`:  `\~`,
        // 其他特殊字符可以根据需要添加
    }

    // 使用 strings.ReplaceAll 进行转义
    for char, escaped := range specialChars {
        input = strings.ReplaceAll(input, char, escaped)
    }
    
    return input
}

func handleError(c *gin.Context, err error, status int) {
    log.Printf("Error: %v", err)
    c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
}

func setupRouter(confVar conf.Config) *gin.Engine {
    // 定义正则表达式，使用 (?i) 使其忽略大小写
    re := regexp.MustCompile("(?i)^(y|true|yes)$")

    if re.MatchString(confVar.ReleaseMode) {
        gin.SetMode(gin.ReleaseMode)
    }
    router := gin.Default()

    // healthz
    router.GET("/healthz", func(c *gin.Context) {
        c.String(http.StatusOK, "ok")
    })

    // // 使用中间件
    // router.Use(apiKeyMiddleware(confVar.XApiKey))

    // 定义允许的 IP 地址和范围
    // allowedIPs := []string{
    //     "127.0.0.1",
    //     "192.168.1.10",     // 具体 IPv4
    //     "2001:db8::1",      // 具体 IPv6
    //     "192.168.1.0/24",   // IPv4 范围
    //     "2001:db8::/32",    // IPv6 范围
    // }

    allowedIPs := strings.Split(confVar.AllowedIp, ",")

    if len(allowedIPs) > 0 {
        // 使用 IP 白名单中间件
        router.Use(IPWhitelistMiddleware(allowedIPs))
    }
    // 定义路由
    router.GET("/api/v1/config", apiKeyMiddleware(confVar.XApiKey), func(c *gin.Context) {
        filePath := confVar.ApisixConfig
        content, err := ioutil.ReadFile(filePath)
        if err != nil {
            handleError(c, err, http.StatusBadRequest)
            return
        }

        // 将文件内容编码为 Base64
        encoded := base64.StdEncoding.EncodeToString(content)
        // 打印 Base64 编码的字符串
        // log.Println("Base64 Encoded Content:")
        // log.Println(encoded)

        c.JSON(http.StatusOK, gin.H{"message": "success","data": encoded })

        
    })

    router.POST("/api/v1/config", apiKeyMiddleware(confVar.XApiKey), func(c *gin.Context) {
        filePath := confVar.ApisixConfig

        var postConfig PostConfig
        // 绑定 JSON 数据到结构体
        if err := c.ShouldBindJSON(&postConfig); err != nil {
            // 如果绑定失败，返回 400 Bad Request
            handleError(c, err, http.StatusBadRequest)
            return
        }
        decodedBytes, err := base64.StdEncoding.DecodeString(postConfig.Data)
        if err != nil {
            handleError(c, err, http.StatusBadRequest)
            return
        }
        // 尝试解析 YAML 文件
        var data interface{}
        if err := yaml.Unmarshal(decodedBytes, &data); err != nil {
            handleError(c, err, http.StatusBadRequest)
            return
        }
        // 写入文件
        file, err := os.Create(filePath)
        if err != nil {
            handleError(c, err, http.StatusBadRequest)
            return
        }
        defer file.Close()
        _, err = file.Write(decodedBytes)
        if err != nil {
            handleError(c, err, http.StatusBadRequest)
            return
        }
        
        c.JSON(http.StatusOK, gin.H{"message": "success"})
        
    })

    router.GET("/api/v1/reload", apiKeyMiddleware(confVar.XApiKey), func(c *gin.Context) {
        log.Printf("Exec cmd: %v", confVar.ApisixReloadCmd )
        cmd := exec.Command("bash", "-c", confVar.ApisixReloadCmd )
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err := cmd.Run()
        outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
        
        if err != nil {
            log.Printf("Error: %v", err)
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error(), "errStr" : errStr })
            return
        }
        
        c.JSON(http.StatusOK, gin.H{"message": "success" ,"outStr" : outStr, "errStr" : errStr })
        
    })

    router.GET("/api/v1/restart", apiKeyMiddleware(confVar.XApiKey), func(c *gin.Context) {
        log.Printf("Exec cmd: %v", confVar.ApisixReStartCmd )
        cmd := exec.Command("bash", "-c", confVar.ApisixReStartCmd )
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err := cmd.Run()
        outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
        
        if err != nil {
            log.Printf("Error: %v", err)
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error(), "errStr" : errStr })
            return
        }
        
        c.JSON(http.StatusOK, gin.H{"message": "success" ,"outStr" : outStr, "errStr" : errStr })
    })
    

    router.GET("/api/v1/stop", apiKeyMiddleware(confVar.XApiKey), func(c *gin.Context) {
        log.Printf("Exec cmd: %v", confVar.ApisixStopCmd )
        cmd := exec.Command("bash", "-c", confVar.ApisixStopCmd )
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err := cmd.Run()
        outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
        
        if err != nil {
            log.Printf("Error: %v", err)
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error(), "errStr" : errStr })
            return
        }
        
        c.JSON(http.StatusOK, gin.H{"message": "success" ,"outStr" : outStr, "errStr" : errStr })
    })

    router.GET("/api/v1/start", apiKeyMiddleware(confVar.XApiKey), func(c *gin.Context) {
        log.Printf("Exec cmd: %v", confVar.ApisixStartCmd )
        cmd := exec.Command("bash", "-c", confVar.ApisixStartCmd )
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err := cmd.Run()
        outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
        
        if err != nil {
            log.Printf("Error: %v", err)
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error(), "errStr" : errStr })
            return
        }
        
        c.JSON(http.StatusOK, gin.H{"message": "success" ,"outStr" : outStr, "errStr" : errStr })
    })
    // 定义根路由的处理程序
    router.GET("/", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"message": ""})
    })

    return router

}


func main() {
    pflag.String("listen", ":5980", "listen address")
    pflag.String("release-mode", "true", "gin.ReleaseMode")
    pflag.String("x-api-key", "your-secret-api-key", "x-api-key")
    pflag.String("allowed-ip", "", "Comma-separated list of allowed IPs")
    pflag.String("apisix-config", "", "apisix-config")
    pflag.String("apisix-reload-cmd", "", "apisix-reload-cmd")
    pflag.String("apisix-stop-cmd", "", "apisix-stop-cmd")
    pflag.String("apisix-start-cmd", "", "apisix-start-cmd")
    pflag.String("apisix-restart-cmd", "", "apisix-restart-cmd")

    // 定义帮助标志
    pflag.BoolP("help", "h", false, "aia, apisix instance agent.")
    pflag.BoolP("version","", false, "print version")
    viper.BindPFlags(pflag.CommandLine)
    pflag.Parse()

    // 检查帮助标志
    if pflag.Lookup("help").Changed {
        pflag.Usage() // 打印帮助信息
        os.Exit(0)    // 退出程序
    }

    if pflag.Lookup("version").Changed {
        fmt.Printf("Version: %s\n", version)
        fmt.Printf("Commit: %s\n", commit)
        fmt.Printf("Build Date: %s\n", buildDate)
        os.Exit(0)    // 退出程序
    }

    confVar := conf.Config{
        Listen: viper.GetString("listen"),
        ReleaseMode: viper.GetString("release-mode"),
        XApiKey: viper.GetString("x-api-key"),
        ApisixConfig: viper.GetString("apisix-config"),
        ApisixReloadCmd: viper.GetString("apisix-reload-cmd"),
        ApisixStopCmd: viper.GetString("apisix-stop-cmd"),
        ApisixStartCmd: viper.GetString("apisix-start-cmd"),
        ApisixReStartCmd: viper.GetString("apisix-restart-cmd"),
        AllowedIp: viper.GetString("allowed-ip"),
    }
    //log.Printf("%+v\n", confVar)

    r := setupRouter(confVar)
    // 启动服务
    log.Printf("Starting server at %s", confVar.Listen)
    err := r.Run(confVar.Listen)
    if err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}

