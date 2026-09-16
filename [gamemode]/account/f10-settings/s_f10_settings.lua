--[[
 * ***********************************************************************************************************************
 * SECURITY REWRITE - Phase 1
 * الثغرات اللي اتقفلت في الملف ده:
 *  [CRIT-1] saveClientAccountSettingsOnServer: كان بيعمل setElementData(source, name, value)
 *           بـ name/value من الكلاينت وعلى أي عنصر -> أي لاعب كان يقدر يدي نفسه/الكل admin_level.
 *  [CRIT-2] updateSetting/updateCharacterSetting: كانوا بيعملوا `client = source` يعني
 *           بيدوسوا على متغير MTA المحمي بقيمة من الكلاينت -> الكتابة في حساب لاعب تاني.
 *  [HIGH-3] loadAccountSettings/loadCharacterSettings: كانوا بياخدوا (player, id) من الكلاينت
 *           -> أي لاعب يقرا إعدادات أي حساب تاني (تسريب بيانات).
 *  [MED-4]  مفيش أي rate limiting -> سبام على الداتابيز.
 *
 * الحل: whitelist صريح للمفاتيح + التحقق من الصلاحية لمفاتيح الـ duty +
 *       قاعدة موحّدة "لو client موجود لازم يساوي source" + rate limit.
 * أوبتمايزيشن: batching للكتابة في الداتابيز بدل REPLACE INTO لكل ضغطة زرار.
 * ***********************************************************************************************************************
]]

local mysql = exports.mysql

-- =====================================================================
-- القوائم المسموحة
-- =====================================================================

-- إعدادات الحساب المسموح للكلاينت يغيّرها
local ALLOWED_ACCOUNT_SETTINGS = {
	["autopark"] = true, ["cellphone_log"] = true, ["hide_hud"] = true,
	["report_panel_mod"] = true, ["speedo"] = true, ["wrn:style"] = true,
	["auto_check"] = true, ["bind_indicators"] = true, ["carradio"] = true,
	["dynamic_lighting"] = true, ["enableNewUIStyle"] = true,
	["enableOverlayDescription"] = true, ["enableOverlayDescriptionNote"] = true,
	["enableOverlayDescriptionPro"] = true, ["enableOverlayDescriptionVeh"] = true,
	["exclusiveGUI"] = true, ["graphic_chatbub"] = true,
	["graphic_chatbub_square"] = true, ["graphic_logs"] = true,
	["graphic_motionblur"] = true, ["graphic_nametags"] = true,
	["graphic_shader_darker_night"] = true, ["graphic_shaderradar"] = true,
	["graphic_shaderveh"] = true, ["graphic_shaderveh_reflect"] = true,
	["graphic_shaderwater"] = true, ["graphic_skyclouds"] = true,
	["graphic_typingicon"] = true, ["groundsnow"] = true,
	["incoming_priority_report_sound"] = true, ["incoming_report_sound"] = true,
	["interior_inactivity_scanner"] = true, ["misc_sounds"] = true,
	["noti_faction_updates"] = true, ["noti_no_noti"] = true,
	["noti_offline_pm"] = true, ["phone_anim"] = true, ["pm_username"] = true,
	["punishment_notification_selector"] = true, ["settings_hud_style"] = true,
	["snowfall"] = true, ["social_classic_user_interface"] = true,
	["social_friend_updates"] = true, ["social_friend_updates_char"] = true,
	["social_friend_updates_msg"] = true, ["social_friend_updates_on_off"] = true,
	["social_friend_updates_sound"] = true, ["social_friends_bypass_pmblock"] = true,
	["social_invite_only"] = true, ["support_center"] = true,
	["talk_anim"] = true, ["togglechatbubbles"] = true, ["togglehud"] = true,
	["vehicle_description_altgr"] = true, ["vehicle_hotkey"] = true,
	["vehicle_inactivity_scanner"] = true, ["vehicle_rims"] = true,
	["weapon_show_selector"] = true, ["xmastreefx"] = true,
	["head_turning"] = true,
}

-- إعدادات الشخصية
local ALLOWED_CHARACTER_SETTINGS = {
	["head_turning"] = true, ["talk_anim"] = true, ["phone_anim"] = true,
	["description"] = true, ["togglechatbubbles"] = true,
}

-- مفاتيح مسموحة بس بشرط صلاحية متحقق منها على السيرفر
local PERMISSION_GATED = {
	["duty_admin"] = function(p) return exports.integration:isPlayerTrialAdmin(p) end,
	["duty_supporter"] = function(p) return exports.integration:isPlayerSupporter(p) end,
}

local MAX_NAME_LEN  = 64
local MAX_VALUE_LEN = 256
local WRITE_COOLDOWN = 250   -- ms بين كل كتابة إعداد

-- =====================================================================
-- أدوات مشتركة
-- =====================================================================

local lastWrite = {}

--[[
	القاعدة الذهبية:
	- لو الحدث جه من الكلاينت -> `client` مظبوط، ولازم يساوي `source`
	- لو الحدث جه من كود السيرفر (triggerEvent) -> `client` = nil، نثق في `source`
	ده بيمنع تزوير الـ source من غير ما يكسر النداءات الداخلية.
]]
local function resolveActor()
	if client then
		if source ~= client then
			outputServerLog("[SEC][f10-settings] source spoof by " .. (getPlayerName(client) or "?"))
			return nil
		end
		return client
	end
	if isElement(source) and getElementType(source) == "player" then
		return source
	end
	return nil
end

local function isThrottled(player)
	local now = getTickCount()
	local last = lastWrite[player]
	if last and (now - last) < WRITE_COOLDOWN then
		return true
	end
	lastWrite[player] = now
	return false
end

-- التحقق من اسم/قيمة الإعداد
local function validateSetting(player, name, value, allowedList)
	if type(name) ~= "string" or #name == 0 or #name > MAX_NAME_LEN then
		return false
	end

	-- نوع القيمة: نص أو رقم أو بوليان فقط (مش جدول/عنصر)
	local vt = type(value)
	if vt ~= "string" and vt ~= "number" and vt ~= "boolean" then
		return false
	end
	if vt == "string" and #value > MAX_VALUE_LEN then
		return false
	end

	-- مفتاح محمي بواسطة الـ anticheat؟ ممنوع نهائيًا
	if exports.anticheat:isElementDataProtected(player, name) and not PERMISSION_GATED[name] then
		outputServerLog("[SEC][f10-settings] " .. (getPlayerName(player) or "?")
			.. " tried to write protected key: " .. name)
		return false
	end

	local gate = PERMISSION_GATED[name]
	if gate then
		if not gate(player) then
			outputServerLog("[SEC][f10-settings] " .. (getPlayerName(player) or "?")
				.. " tried to set " .. name .. " without permission")
			return false
		end
		return true
	end

	if not allowedList[name] then
		outputServerLog("[SEC][f10-settings] " .. (getPlayerName(player) or "?")
			.. " tried unknown setting: " .. name)
		return false
	end

	return true
end

-- =====================================================================
-- الكتابة في الداتابيز
-- =====================================================================

function updateSetting(name, value)
	local player = resolveActor()
	if not player then return false end
	if not validateSetting(player, name, value, ALLOWED_ACCOUNT_SETTINGS) then return false end

	local id = tonumber(getElementData(player, "account:id"))
	if not id then return false end

	mysql:query_free("REPLACE INTO account_settings (id, name, value) VALUES ('"
		.. id .. "', '" .. mysql:escape_string(tostring(name)) .. "', '"
		.. mysql:escape_string(tostring(value)) .. "')")
	return true
end
addEvent("accounts:settings:update", true)
addEventHandler("accounts:settings:update", root, updateSetting)

function updateCharacterSetting(name, value)
	local player = resolveActor()
	if not player then return false end
	if not validateSetting(player, name, value, ALLOWED_CHARACTER_SETTINGS) then return false end

	local id = tonumber(getElementData(player, "dbid"))
	if not id then return false end

	mysql:query_free("REPLACE INTO character_settings (id, name, value) VALUES ('"
		.. id .. "', '" .. mysql:escape_string(tostring(name)) .. "', '"
		.. mysql:escape_string(tostring(value)) .. "')")
	return true
end
addEvent("accounts:settings:updateCharacterSetting", true)
addEventHandler("accounts:settings:updateCharacterSetting", root, updateCharacterSetting)

-- =====================================================================
-- القراءة من الداتابيز
-- =====================================================================

--[[
	ملاحظة مهمة:
	الدالة دي بينداها كود اللوجين مباشرة (login-panel/server.lua) وبيبعت الـ id
	الصح من الداتابيز. فسبناها بتثق في الباراميترات لأنها مش متاحة للكلاينت.
	الكلاينت بيوصل عن طريق الـ wrapper تحت بس، واللي بيتجاهل أي باراميتر بيبعته.
]]
function loadAccountSettings(player, id)
	if not isElement(player) or not id then return false end
	id = tonumber(id)
	if not id then return false end

	local settings = {}
	local count = 0
	local query1 = mysql:query("SELECT `name`, `value` FROM `account_settings` WHERE `id` = '" .. id .. "'")
	if not query1 then return false end
	while true do
		local row = mysql:fetch_assoc(query1)
		if not row then break end

		-- ما ينفعش نرجّع duty لحد مش أدمن حتى لو متسجّل في الداتابيز
		if (row.name == "duty_admin" and not exports.integration:isPlayerTrialAdmin(player))
		or (row.name == "duty_supporter" and not exports.integration:isPlayerSupporter(player)) then
			row.value = 0
		end

		count = count + 1
		settings[count] = { row.name, row.value }
	end
	mysql:free_result(query1)

	if count > 0 then
		triggerClientEvent(player, "accounts:settings:loadAccountSettings", player, settings)
	end
	return true
end
-- [SECURITY] كان أي لاعب يقدر يقرا إعدادات أي حساب برقمه. دلوقتي الباراميترات بتتجاهل.
addEvent("accounts:settings:loadAccountSettings", true)
addEventHandler("accounts:settings:loadAccountSettings", root, function()
	if not client then return end
	if source ~= client then
		exports.global:logSecurityViolation(client, "accounts:settings:loadAccountSettings", "SOURCE_SPOOF")
		return
	end
	local id = tonumber(getElementData(client, "account:id"))
	if not id then return end
	loadAccountSettings(client, id)
end)

-- نفس المنطق: بينداها s_characters.lua مباشرة بالـ characterID الصح
function loadCharacterSettings(player, id)
	if not isElement(player) or not id then return false end
	id = tonumber(id)
	if not id then return false end

	local settings = {}
	local count = 0
	local query1 = mysql:query("SELECT `name`, `value` FROM `character_settings` WHERE `id` = '" .. id .. "'")
	if not query1 then return false end
	while true do
		local row = mysql:fetch_assoc(query1)
		if not row then break end
		count = count + 1
		settings[count] = { row.name, row.value }
	end
	mysql:free_result(query1)

	if count > 0 then
		triggerClientEvent(player, "accounts:settings:loadCharacterSettings", player, settings)
	end
	return true
end
addEvent("accounts:settings:loadCharacterSettings", true)
addEventHandler("accounts:settings:loadCharacterSettings", root, function()
	if not client then return end
	if source ~= client then
		exports.global:logSecurityViolation(client, "accounts:settings:loadCharacterSettings", "SOURCE_SPOOF")
		return
	end
	local id = tonumber(getElementData(client, "dbid"))
	if not id then return end
	loadCharacterSettings(client, id)
end)

-- =====================================================================
-- إعادة الاتصال
-- =====================================================================

function reconnectPlayer()
	if not client then return false end
	if source ~= client then return false end
	if isThrottled(client) then return false end
	redirectPlayer(client, "", 0)
	return true
end
addEvent("accounts:settings:reconnectPlayer", true)
addEventHandler("accounts:settings:reconnectPlayer", root, reconnectPlayer)

-- =====================================================================
-- الكاش المؤقت اللي بيتحفظ عند الخروج
-- =====================================================================

local clientAccountSettings = {}
local clientCharacterSettings = {}

local function flushSettings(player)
	local acc = clientAccountSettings[player]
	if acc then
		for i = 1, #acc do
			triggerEvent("accounts:settings:update", player, acc[i][1], acc[i][2])
		end
		clientAccountSettings[player] = nil
	end

	local chr = clientCharacterSettings[player]
	if chr then
		for i = 1, #chr do
			triggerEvent("accounts:settings:updateCharacterSetting", player, chr[i][1], chr[i][2])
		end
		clientCharacterSettings[player] = nil
	end
end

function whenPlayerQuit(quitType)
	flushSettings(source)
	lastWrite[source] = nil
end
addEventHandler("onPlayerQuit", root, whenPlayerQuit)

function whenPlayerChangeChar()
	flushSettings(source)
end
addEventHandler("accounts:characters:change", root, whenPlayerChangeChar)

-- =====================================================================
-- استقبال الإعدادات من الكلاينت (كانت دي الثغرة الأم)
-- =====================================================================

local function bufferSetting(store, player, name, value)
	local list = store[player]
	if not list then
		list = {}
		store[player] = list
	end
	for i = 1, #list do
		if list[i][1] == name then
			list[i][2] = value
			return
		end
	end
	list[#list + 1] = { name, value }
end

function saveClientAccountSettingsOnServer(name, value)
	local player = resolveActor()
	if not player then return false end
	if isThrottled(player) then return false end
	if not validateSetting(player, name, value, ALLOWED_ACCOUNT_SETTINGS) then return false end

	bufferSetting(clientAccountSettings, player, name, value)

	-- الكتابة بتمر من الـ anticheat -> كتابة موثوقة، ومستحيل تلمس مفتاح محمي
	exports.anticheat:changeProtectedElementDataEx(player, name, value, true)

	if name == "duty_admin" or name == "duty_supporter" then
		exports.global:updateNametagColor(player)
	end
	return true
end
addEvent("saveClientAccountSettingsOnServer", true)
addEventHandler("saveClientAccountSettingsOnServer", root, saveClientAccountSettingsOnServer)

function saveClientCharacterSettingsOnServer(name, value)
	local player = resolveActor()
	if not player then return false end
	if isThrottled(player) then return false end
	if not validateSetting(player, name, value, ALLOWED_CHARACTER_SETTINGS) then return false end

	bufferSetting(clientCharacterSettings, player, name, value)
	exports.anticheat:changeProtectedElementDataEx(player, name, value, true)
	return true
end
addEvent("saveClientCharacterSettingsOnServer", true)
addEventHandler("saveClientCharacterSettingsOnServer", root, saveClientCharacterSettingsOnServer)
