package ipgeo

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"

	"github.com/nxtrace/NTrace-core/util"
)

const (
	myAPIBaseURL = "https://bcd5354e28ea.b-cdn.net/"
)

func MyAPI(ip string, timeout time.Duration, _ string, _ bool) (*IPGeoData, error) {
	apiKey := util.GetEnvDefault("NEXTTRACE_MYAPI_KEY", "")
	if apiKey == "" {
		return &IPGeoData{}, fmt.Errorf("myapi: NEXTTRACE_MYAPI_KEY environment variable is not set")
	}

	url := myAPIBaseURL + "?key=" + apiKey + "&ip=" + ip
	client := util.NewGeoHTTPClient(timeout)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("myapi: create request: %w", err)
	}
	req.Header.Set("User-Agent", "NextTrace/custom")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("myapi: request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("myapi: read body: %w", err)
	}

	res := gjson.ParseBytes(body)
	geo := res.Get("geo")

	// ASN: 去掉 "AS" 前缀
	asn := strings.TrimPrefix(geo.Get("asn").String(), "AS")

	lat, _ := strconv.ParseFloat(geo.Get("latitude").String(), 64)
	lng, _ := strconv.ParseFloat(geo.Get("longitude").String(), 64)

	owner := geo.Get("org").String()
	isp := geo.Get("isp").String()

	// Anycast 特殊处理
	if geo.Get("is_anycast").Bool() {
		return &IPGeoData{
			Asnumber: asn,
			Country:  "ANYCAST",
			Prov:     "ANYCAST",
			Owner:    owner,
			Isp:      isp,
		}, nil
	}

	// 构建 privacy/threat/proxy 紧凑标签，追加到 Owner 末尾
	tags := buildMyAPITags(res)
	if tags != "" {
		if owner != "" {
			owner += " " + tags
		} else if isp != "" {
			owner = isp + " " + tags
		} else {
			owner = tags
		}
	}

	return &IPGeoData{
		Asnumber:  asn,
		Country:   geo.Get("country").String(),
		CountryEn: geo.Get("country_en").String(),
		Prov:      geo.Get("region").String(),
		ProvEn:    geo.Get("region_en").String(),
		City:      geo.Get("city").String(),
		CityEn:    geo.Get("city_en").String(),
		District:  geo.Get("district").String(),
		Owner:     owner,
		Isp:       isp,
		Domain:    geo.Get("domain").String(),
		Lat:       lat,
		Lng:       lng,
	}, nil
}

// buildMyAPITags 从 privacy/threat_intelligence/proxy_intelligence 生成紧凑标签
// 例如: "[DC] [Threat:webattack,ddos] [Proxy]"
func buildMyAPITags(res gjson.Result) string {
	var tags []string

	// privacy 标签
	privacy := res.Get("privacy")
	if privacy.Exists() {
		if privacy.Get("is_datacenter").Bool() {
			tags = append(tags, "[DC]")
		}
		if privacy.Get("is_anonymous").Bool() && !privacy.Get("is_datacenter").Bool() {
			tags = append(tags, "[Anon]")
		}
		if privacy.Get("is_tor").Bool() {
			tags = append(tags, "[Tor]")
		}
		if privacy.Get("is_icloud_relay").Bool() {
			tags = append(tags, "[iCloud]")
		}
		if privacy.Get("is_known_bot").Bool() {
			tags = append(tags, "[Bot]")
		}
	}

	// threat_intelligence 标签
	threat := res.Get("threat_intelligence")
	if threat.Exists() && threat.Get("is_threat").Bool() {
		abuse := threat.Get("recent_abuse")
		if abuse.Exists() && abuse.IsArray() && len(abuse.Array()) > 0 {
			var items []string
			for _, a := range abuse.Array() {
				items = append(items, a.String())
			}
			tags = append(tags, "[Threat:"+strings.Join(items, ",")+"]")
		} else {
			tags = append(tags, "[Threat]")
		}
	}

	// proxy_intelligence 标签
	proxy := res.Get("proxy_intelligence")
	if proxy.Exists() && proxy.Get("is_proxy").Bool() {
		tags = append(tags, "[Proxy]")
	}

	return strings.Join(tags, " ")
}
