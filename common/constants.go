package common

import "time"

var StartTime = time.Now().Unix() // unit: second
var Version = "v1.12.2"           // this hard coding will be replaced automatically when building, no need to manually change

var DefaultOpenaiModelList = []string{
	"gpt-4.1",
	"o1",
	"o4-mini-high",
	"claude-3-7-sonnet-thinking",
	"claude-3-7-sonnet",
	"gemini-2.5-pro",
	"gemini-2.0-flash",
	"deep-seek-v3",
	"deep-seek-r1",

	"flux",
	"flux-speed",
	"flux-pro/ultra",
	"ideogram",
	"ideogram/V_2A",
	"recraft-v3",
	"dall-e-3",
	"imagen3",
	"gpt-image-1",
}

var TextModelList = []string{
	"gpt-4.1",
	"o1",
	"o4-mini-high",
	"claude-3-7-sonnet-thinking",
	"claude-3-7-sonnet",
	"gemini-2.5-pro",
	"gemini-2.0-flash",
	"deep-seek-v3",
	"deep-seek-r1",
}

var MixtureModelList = []string{
	"gpt-4o",
	"claude-3-7-sonnet",
	"gemini-2.0-flash",
}

var ImageModelList = []string{
	"flux",
	"flux-speed",
	"flux-pro/ultra",
	"ideogram",
	"ideogram/V_2A",
	"recraft-v3",
	"dall-e-3",
	"imagen3",
	"imagen3",
	"gpt-image-1",
}

var VideoModelList = []string{
	"kling/v1.6/standard",
	"pixverse/v3.5/turbo",
	"lumadream/ray-2",
	"gemini/veo2",
	"hunyuan",
}

//
