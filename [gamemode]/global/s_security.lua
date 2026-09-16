--[[
 * ***********************************************************************************************************************
 * OwlGamingPlus - Security Core  (NEW FILE - Phase 1)
 * ***********************************************************************************************************************
 * الغرض: طبقة واحدة بتتعامل مع كل الـ remote events بشكل آمن، بدل ما نكرر
 *        نفس فحوصات الأمان 1400 مرة في كل الجيم مود.
 *
 * بتضمن:
 *   - منع تزوير الـ source  (source لازم يساوي client)
 *   - اللاعب لازم يكون داخل حسابه فعلًا
 *   - فحص صلاحية اختياري متحقق منه على السيرفر
 *   - Rate limiting لكل لاعب/حدث (منع السبام والـ DoS على الداتابيز)
 *   - تسجيل كل محاولة مرفوضة في ملف لوج + تنبيه الأدمنز
 *   - تمرير `client` دايمًا كباراميتر أول -> يقفل نمط "confused deputy"
 *
 * أوبتمايزيشن:
 *   - جدول الكول داون بيتمسح تلقائي عند الخروج (مفيش memory leak)
 *   - تنظيف دوري خفيف كل 5 دقايق للـ entries القديمة
 *   - المسار السليم (happy path) فيه أقل عدد ممكن من الفحوصات
 * ***********************************************************************************************************************
]]

local LOG_FILE        = "security.log"
local ADMIN_ALERT     = true
local ALERT_THRESHOLD = 3      -- عدد المحاولات قبل ما ننبه الأدمنز
local ALERT_WINDOW    = 60000  -- خلال كام ملي ثانية

local cooldowns  = {}  -- [player] = { [eventName] = tick }
local violations = {}  -- [player] = { count = n, first = tick }

-- =====================================================================
-- اللوج
-- =====================================================================

local function writeLog(line)
	local f
	if fileExists(LOG_FILE) then
		f = fileOpen(LOG_FILE)
		if f then fileSetPos(f, fileGetSize(f)) end
	else
		f = fileCreate(LOG_FILE)
	end
	if f then
		fileWrite(f, line .. "\n")
		fileClose(f)
	end
end

function logSecurityViolation(player, eventName, reason)
	local name    = isElement(player) and (getPlayerName(player) or "?") or "unknown"
	local serial  = isElement(player) and (getPlayerSerial(player) or "?") or "?"
	local ip      = isElement(player) and (getPlayerIP(player) or "?") or "?"

	writeLog(("[%s] %s | player=%s serial=%s ip=%s | event=%s"):format(
		os.date("%Y-%m-%d %H:%M:%S"), reason, name, serial, ip, tostring(eventName)))

	if not ADMIN_ALERT or not isElement(player) then return end

	local now = getTickCount()
	local v = violations[player]
	if not v or (now - v.first) > ALERT_WINDOW then
		v = { count = 0, first = now, alerted = false }
		violations[player] = v
	end
	v.count = v.count + 1

	if v.count >= ALERT_THRESHOLD and not v.alerted then
		v.alerted = true
		exports.global:sendMessageToAdmins(
			"[SECURITY] " .. name .. " triggered " .. v.count ..
			" blocked events (last: " .. tostring(eventName) .. ")", true)
	end
end

-- =====================================================================
-- الدالة الأساسية
-- =====================================================================

--[[
	addSecureEvent(eventName, handler, options)

	options = {
		permission  = function(player) return bool end,   -- فحص صلاحية اختياري
		cooldown    = 500,                                -- ms بين كل نداء
		requireLogin = true,                              -- الافتراضي true
		allowServer  = false,                             -- يسمح بنداء داخلي من السيرفر
	}

	الـ handler بيستقبل: handler(thePlayer, ...)
	`thePlayer` دايمًا هو اللاعب الحقيقي اللي بعت الحدث - مستحيل يتزوّر.
]]
function addSecureEvent(eventName, handler, options)
	if type(eventName) ~= "string" or type(handler) ~= "function" then
		outputDebugString("[SECURITY] addSecureEvent: bad arguments for " .. tostring(eventName), 1)
		return false
	end

	options = options or {}
	local permission   = options.permission
	local cooldown     = options.cooldown
	local requireLogin = (options.requireLogin ~= false)
	local allowServer  = options.allowServer

	addEvent(eventName, true)
	addEventHandler(eventName, root, function(...)
		-- نداء داخلي من كود السيرفر
		if not client then
			if allowServer and isElement(source) and getElementType(source) == "player" then
				return handler(source, ...)
			end
			return
		end

		-- 1) منع تزوير الـ source
		if source ~= client then
			logSecurityViolation(client, eventName, "SOURCE_SPOOF")
			return
		end

		-- 2) لازم يكون داخل حسابه
		if requireLogin and getElementData(client, "loggedin") ~= 1 then
			logSecurityViolation(client, eventName, "NOT_LOGGED_IN")
			return
		end

		-- 3) Rate limit
		if cooldown then
			local now = getTickCount()
			local t = cooldowns[client]
			if not t then
				t = {}
				cooldowns[client] = t
			end
			if t[eventName] and (now - t[eventName]) < cooldown then
				return -- سبام عادي، مش محتاج لوج
			end
			t[eventName] = now
		end

		-- 4) الصلاحية
		if permission and not permission(client) then
			logSecurityViolation(client, eventName, "PERMISSION_DENIED")
			return
		end

		return handler(client, ...)
	end)

	return true
end

-- =====================================================================
-- نسخة تشتغل عبر الـ exports (الريسورسات التانية)
-- =====================================================================
--
-- في MTA مينفعش تبعت دالة بين ريسورسين، فالصلاحية بتتبعت كـ نص.
--
local PERMISSIONS = {
	["none"]         = function() return true end,
	["trialadmin"]   = function(p) return exports.integration:isPlayerTrialAdmin(p) end,
	["admin"]        = function(p) return exports.integration:isPlayerAdmin(p) end,
	["senioradmin"]  = function(p) return exports.integration:isPlayerSeniorAdmin(p) end,
	["leadadmin"]    = function(p) return exports.integration:isPlayerLeadAdmin(p) end,
	["headadmin"]    = function(p) return exports.integration:isPlayerHeadAdmin(p) end,
	["supporter"]    = function(p) return exports.integration:isPlayerSupporter(p) end,
	["scripter"]     = function(p) return exports.integration:isPlayerScripter(p) end,
	["leadscripter"] = function(p) return exports.integration:isPlayerLeadScripter(p) end,
	["staff"]        = function(p) return exports.integration:isPlayerStaff(p) end,
	["vct"]          = function(p) return exports.integration:isPlayerVCTMember(p) end,
	["mapper"]       = function(p) return exports.integration:isPlayerMappingTeamMember(p) end,
	["fmt"]          = function(p) return exports.integration:isPlayerFMTMember(p) end,
}

--[[
	validateSecureCall(theClient, theSource, eventName, permName, cooldownMs, requireLogin)
	بترجع اللاعب الحقيقي لو كل حاجة تمام، أو false لو الاستدعاء مرفوض.

	الاستخدام في أي ريسورس تاني:

		local function secure(eventName, handler, perm, cooldown)
			addEvent(eventName, true)
			addEventHandler(eventName, root, function(...)
				local p = exports.global:validateSecureCall(client, source, eventName, perm, cooldown)
				if not p then return end
				return handler(p, ...)
			end)
		end
]]
function validateSecureCall(theClient, theSource, eventName, permName, cooldownMs, requireLogin)
	if not theClient then return false end
	if not isElement(theClient) then return false end

	if theSource ~= theClient then
		logSecurityViolation(theClient, eventName, "SOURCE_SPOOF")
		return false
	end

	if requireLogin ~= false and getElementData(theClient, "loggedin") ~= 1 then
		logSecurityViolation(theClient, eventName, "NOT_LOGGED_IN")
		return false
	end

	if cooldownMs then
		local now = getTickCount()
		local t = cooldowns[theClient]
		if not t then
			t = {}
			cooldowns[theClient] = t
		end
		if t[eventName] and (now - t[eventName]) < cooldownMs then
			return false
		end
		t[eventName] = now
	end

	if permName and permName ~= "none" then
		local fn = PERMISSIONS[permName]
		if not fn then
			outputDebugString("[SECURITY] unknown permission name: " .. tostring(permName), 1)
			return false
		end
		if not fn(theClient) then
			logSecurityViolation(theClient, eventName, "PERMISSION_DENIED")
			return false
		end
	end

	return theClient
end

-- =====================================================================
-- مساعدات للتحقق من المدخلات
-- =====================================================================

-- رقم في نطاق محدد
function secureNumber(value, min, max)
	local n = tonumber(value)
	if not n then return nil end
	if n ~= n then return nil end                 -- NaN
	if min and n < min then return nil end
	if max and n > max then return nil end
	return n
end

-- عدد صحيح
function secureInt(value, min, max)
	local n = secureNumber(value, min, max)
	if not n then return nil end
	return math.floor(n)
end

-- نص بطول محدود
function secureString(value, maxLen)
	if type(value) ~= "string" then return nil end
	if #value == 0 then return nil end
	if maxLen and #value > maxLen then return nil end
	return value
end

-- عنصر من نوع معيّن وموجود فعلًا
function secureElement(value, elementType)
	if not isElement(value) then return nil end
	if elementType and getElementType(value) ~= elementType then return nil end
	return value
end

-- لاعب قريب من لاعب تاني (لمنع التحكم في ناس على الخريطة كلها)
function secureNearbyPlayer(actor, target, maxDistance)
	if not isElement(actor) or not isElement(target) then return nil end
	if getElementType(target) ~= "player" then return nil end
	if getElementDimension(actor) ~= getElementDimension(target) then return nil end
	if getElementInterior(actor) ~= getElementInterior(target) then return nil end

	local ax, ay, az = getElementPosition(actor)
	local tx, ty, tz = getElementPosition(target)
	local dx, dy, dz = ax - tx, ay - ty, az - tz
	-- مقارنة المربعات أسرع من getDistanceBetweenPoints3D (مفيش sqrt)
	local limit = (maxDistance or 5)
	if (dx * dx + dy * dy + dz * dz) > (limit * limit) then return nil end
	return target
end

-- =====================================================================
-- التنظيف
-- =====================================================================

local function cleanupPlayer()
	cooldowns[source]  = nil
	violations[source] = nil
end
addEventHandler("onPlayerQuit", root, cleanupPlayer)

-- تنظيف دوري خفيف للـ entries القديمة (لو عنصر اتمسح من غير onPlayerQuit)
setTimer(function()
	for el in pairs(cooldowns) do
		if not isElement(el) then cooldowns[el] = nil end
	end
	for el in pairs(violations) do
		if not isElement(el) then violations[el] = nil end
	end
end, 300000, 0)
