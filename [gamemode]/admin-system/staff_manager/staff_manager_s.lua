--[[
* ***********************************************************************************************************************
* Copyright (c) 2015 OwlGaming Community - All Rights Reserved
* All rights reserved. This program and the accompanying materials are private property belongs to OwlGaming Community
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* ***********************************************************************************************************************
]]

local mysql = exports.mysql

-- =====================================================================
-- [SECURITY] غلاف آمن لكل الـ remote events في الملف ده
-- بيتأكد إن: اللاعب حقيقي + الـ source مش مزوّر + عنده الصلاحية + مش بيسبم
-- =====================================================================
local function secure(eventName, handler, perm, cooldown)
	addEvent(eventName, true)
	addEventHandler(eventName, root, function(...)
		if not client then return end
		local thePlayer = exports.global:validateSecureCall(client, source, eventName, perm, cooldown)
		if not thePlayer then return end
		return handler(thePlayer, ...)
	end)
end

-- من له حق فتح/تعديل إدارة الطاقم
local function canManageStaff(p)
	return exports.integration:isPlayerSeniorAdmin(p)
		or exports.integration:isPlayerLeadScripter(p)
end

local staffTitles = exports.integration:getStaffTitles()
function getStaffInfo(thePlayer, username, error)
	-- [SECURITY] كان بياخد source (قابل للتزوير) ومن غير أي فحص صلاحية
	if not canManageStaff(thePlayer) then
		exports.global:logSecurityViolation(thePlayer, "staff:getStaffInfo", "PERMISSION_DENIED")
		return false
	end
	username = exports.global:secureString(username, 64)
	if not username then return false end
	local error1 = error
	dbQuery(function(qh, username, error, source)
		local result = dbPoll(qh, 0)
		if result and #result > 0 then
			local changelogs = {}
			local mQuery1 = nil
			mQuery1 = mysql:query("SELECT (CASE WHEN to_rank>from_rank THEN 1 ELSE 0 END) AS promoted, s.id, s.userid, team, from_rank, to_rank, s.`by` AS `by`, details, DATE_FORMAT(date,'%b %d, %Y %h:%i %p') AS date FROM staff_changelogs s WHERE s.userid="..result[1]["id"].." ORDER BY id DESC")
			while true do
				local row = mysql:fetch_assoc(mQuery1)
				if not row then break end
				row.userid = exports.cache:getUsernameFromId(row.userid)
				row.by = exports.cache:getUsernameFromId(row.by)
				table.insert(changelogs, row )
			end
			mysql:free_result(mQuery1)
			local staffInfo = {}
			staffInfo.user = result[1]
			staffInfo.changelogs = changelogs
			staffInfo.error = error1
			triggerClientEvent(thePlayer, "openStaffManager", thePlayer, staffInfo)
		end
	end, {username, error, source}, exports.mysql:getConn(), "SELECT id, username, admin, supporter, vct, scripter, mapper, fmt FROM accounts WHERE username=?", username)
end
secure("staff:getStaffInfo", getStaffInfo, "none", 500)

function getTeamsData(thePlayer)
	if not canManageStaff(thePlayer) then
		exports.global:logSecurityViolation(thePlayer, "staff:getTeamsData", "PERMISSION_DENIED")
		return false
	end
	staffTitles = exports.integration:getStaffTitles()
	local users = {}
	dbQuery(
		function(qh, staffTitles, users)
			local result = dbPoll(qh, 0)
			if result then
				for _, row in pairs(result) do
					for i, k in ipairs(staffTitles) do
						if not users[i] then users[i] = {} end
						-- [OPTIMIZATION] عدد الريبورتات بقى جاي مع نفس الاستعلام (LEFT JOIN)
						-- بدل استعلام حاجب (dbPoll -1) لكل صف × 6 فرق = كان بيعلّق السيرفر
						row.adminreports = tonumber(row.adminreports) or 0
						if tonumber(row.admin) > 0 and i == 1 then
							if not row.rank then row.rank = {} end
							row.rank[i] = tonumber(row.admin)
							table.insert(users[i], row)
						end
						if tonumber(row.supporter) > 0 and i == 2 then
							if not row.rank then row.rank = {} end
							row.rank[i] = tonumber(row.supporter)
							table.insert(users[i], row)
						end
						if tonumber(row.vct) > 0 and i == 3 then
							if not row.rank then row.rank = {} end
							row.rank[i] = tonumber(row.vct)
							table.insert(users[i], row)
						end
						if tonumber(row.scripter) > 0 and i == 4 then
							if not row.rank then row.rank = {} end
							row.rank[i] = tonumber(row.scripter)
							table.insert(users[i], row)
						end
						if tonumber(row.mapper) > 0 and i == 5 then
							if not row.rank then row.rank = {} end
							row.rank[i] = tonumber(row.mapper)
							table.insert(users[i], row)
						end
						if tonumber(row.fmt) > 0 and i == 6 then
							if not row.rank then row.rank = {} end
							row.rank[i] = tonumber(row.fmt)
							table.insert(users[i], row)
						end
					end
				end
				triggerClientEvent(thePlayer, "openStaffManager", thePlayer, nil, users )
			else
				dbFree(qh)
			end
		end
	, {staffTitles, users}, exports.mysql:getConn(), "SELECT a.id, a.username, a.admin, a.supporter, a.vct, a.scripter, a.mapper, a.fmt, COALESCE(d.adminreports, 0) AS adminreports FROM accounts a LEFT JOIN account_details d ON d.account_id = a.id WHERE a.admin > 0 OR a.supporter > 0 OR a.vct > 0 OR a.scripter > 0 OR a.mapper > 0 OR a.fmt > 0 GROUP BY a.id ORDER BY a.admin DESC, a.supporter DESC, a.vct DESC, a.scripter DESC, a.mapper DESC")
end
secure("staff:getTeamsData", getTeamsData, "none", 2000)

function getChangelogs(thePlayer)
	if not canManageStaff(thePlayer) then
		exports.global:logSecurityViolation(thePlayer, "staff:getChangelogs", "PERMISSION_DENIED")
		return false
	end
	local changelogs = {}
	local mQuery1 = nil
	mQuery1 = mysql:query("SELECT (CASE WHEN to_rank>from_rank THEN 1 ELSE 0 END) AS promoted, s.id, s.userid, team, from_rank, to_rank, s.`by` AS `by`, details, DATE_FORMAT(date,'%b %d, %Y %h:%i %p') AS date FROM staff_changelogs s ORDER BY id DESC")
	while true do
		local row = mysql:fetch_assoc(mQuery1)
		if not row then break end
		row.userid = exports.cache:getUsernameFromId(row.userid)
		row.by = exports.cache:getUsernameFromId(row.by)
		table.insert(changelogs, row )
	end
	mysql:free_result(mQuery1)
	triggerClientEvent(thePlayer, "openStaffManager", thePlayer, nil, nil, changelogs )
end
secure("staff:getChangelogs", getChangelogs, "none", 2000)

-- الحد الأقصى لكل فريق (index = team) - أي رقم برّه ده مرفوض
local MAX_RANK = { [1] = 5, [2] = 2, [3] = 2, [4] = 3, [5] = 2, [6] = 2 }

function editStaff(thePlayer, userid, ranks, details)
	-- [SECURITY] الفحص القديم كان: `if not A or not B then deny`
	-- ده منطقيًا معناه "لازم الاتنين مع بعض"، فكان بيمنع السينيور أدمن الشرعي.
	-- الصح: أي واحد فيهم يكفي.
	if not canManageStaff(thePlayer) then
		outputChatBox("You are not authorized to change ranks!", thePlayer, 255, 0, 0)
		exports.global:logSecurityViolation(thePlayer, "staff:editStaff", "PERMISSION_DENIED")
		return false
	end

	userid = exports.global:secureInt(userid, 1)
	if not userid then
		outputChatBox("Internal Error!", thePlayer, 255, 0, 0)
		return false
	end

	-- [SECURITY] ranks كانت بتتحط في الاستعلام مباشرة من غير أي تحقق -> SQL injection
	-- + مكانش فيه حد أقصى للرتبة (رتبة 999 كانت ممكنة)
	if type(ranks) ~= "table" then return false end
	local cleanRanks = {}
	for i = 1, 6 do
		if ranks[i] ~= nil then
			local r = exports.global:secureInt(ranks[i], 0, MAX_RANK[i])
			if not r then
				outputChatBox("Invalid rank value.", thePlayer, 255, 0, 0)
				exports.global:logSecurityViolation(thePlayer, "staff:editStaff", "INVALID_RANK")
				return false
			end
			cleanRanks[i] = r
		end
	end

	-- [SECURITY] ممنوع حد يرفّع نفسه، أو يدّي رتبة أعلى من رتبته هو
	local myAdmin = exports.integration:getAdminLevel(thePlayer)
	if cleanRanks[1] and cleanRanks[1] >= myAdmin and not exports.integration:isPlayerHeadAdmin(thePlayer) then
		outputChatBox("You cannot assign a rank equal to or above your own.", thePlayer, 255, 0, 0)
		return false
	end
	if tonumber(getElementData(thePlayer, "account:id")) == userid and not exports.integration:isPlayerHeadAdmin(thePlayer) then
		outputChatBox("You cannot edit your own staff rank.", thePlayer, 255, 0, 0)
		exports.global:logSecurityViolation(thePlayer, "staff:editStaff", "SELF_PROMOTION_ATTEMPT")
		return false
	end

	ranks = cleanRanks

	if details ~= nil then
		details = exports.global:secureString(details, 512) or ""
	end

	local target = false
	for _, player in ipairs(getElementsByType("player")) do
		if tonumber(getElementData(player, "account:id")) == userid then
			target = player
			break
		end
	end
	staffTitles = exports.integration:getStaffTitles()
	dbQuery(function(qh, userid, staffTitles, target, ranks, details, thePlayer)
		local result = dbPoll(qh, 0)
		if result then
			local user = result[1]
			local tail = ''
			if details and string.len(details)>0 then
				details = "'"..mysql:escape_string(details).."'"
			else
				details = "NULL"
			end
			if ranks[1] and ranks[1] ~= tonumber(user.admin) then
				tail = tail.."admin="..ranks[1]..","
				mysql:query_free("INSERT INTO staff_changelogs SET userid="..userid..", details="..details..", `by`="..getElementData(thePlayer, "account:id")..", team=1, from_rank="..user.admin..", to_rank="..ranks[1])
				exports.global:sendMessageToStaff("[STAFF UPDATE] "..exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[1] > tonumber(user.admin) and "promoted" or "demoted").." '"..user.username.."' from "..staffTitles[1][tonumber(user.admin)].." to "..staffTitles[1][ranks[1]]..".", true)
				exports.announcement:makePlayerNotification(target or user.id, "Staff Rank Updated", exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[1] > tonumber(user.admin) and "promoted" or "demoted").." you from "..staffTitles[1][tonumber(user.admin)].." to "..staffTitles[1][ranks[1]]..". \n" .. (ranks[1] > tonumber(user.admin) and "Congratulations!" or "Sorry!"))
				if target then exports.anticheat:changeProtectedElementDataEx(target, "admin_level", ranks[1], true) end
				if ranks[1] == 0 then -- Remove all tickets if they get removed from admin
					dbExec(exports.mysql:getConn(), "UPDATE `tc_tickets` SET `assign_to`=NULL WHERE `assign_to`=?", userid)
				end
			end
			if ranks[2] and ranks[2] ~= tonumber(user.supporter) then
				tail = tail.."supporter="..ranks[2]..","
				mysql:query_free("INSERT INTO staff_changelogs SET userid="..userid..", details="..details..", `by`="..getElementData(thePlayer, "account:id")..", team=2, from_rank="..user.supporter..", to_rank="..ranks[2])
				exports.global:sendMessageToStaff("[STAFF UPDATE] "..exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[2] > tonumber(user.supporter) and "promoted" or "demoted").." '"..user.username.."' from "..staffTitles[2][tonumber(user.supporter)].." to "..staffTitles[2][ranks[2]]..".", true)
				exports.announcement:makePlayerNotification(target or user.id, "Staff Rank Updated", exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[2] > tonumber(user.supporter) and "promoted" or "demoted").." you from "..staffTitles[2][tonumber(user.supporter)].." to "..staffTitles[2][ranks[2]]..". \n" .. (ranks[2] > tonumber(user.supporter) and "Congratulations!" or "Sorry!"))
				if target then exports.anticheat:changeProtectedElementDataEx(target, "supporter_level", ranks[2], true) end
		
			end
			if ranks[3] and ranks[3] ~= tonumber(user.vct) then
				tail = tail.."vct="..ranks[3]..","
				mysql:query_free("INSERT INTO staff_changelogs SET userid="..userid..", details="..details..", `by`="..getElementData(thePlayer, "account:id")..", team=3, from_rank="..user.vct..", to_rank="..ranks[3])
				exports.global:sendMessageToStaff("[STAFF UPDATE] "..exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[3] > tonumber(user.vct) and "promoted" or "demoted").." '"..user.username.."' from "..staffTitles[3][tonumber(user.vct)].." to "..staffTitles[3][ranks[3]]..".", true)
				exports.announcement:makePlayerNotification(target or user.id, "Staff Rank Updated", exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[3] > tonumber(user.vct) and "promoted" or "demoted").." you from "..staffTitles[3][tonumber(user.vct)].." to "..staffTitles[3][ranks[3]]..". \n" .. (ranks[3] > tonumber(user.vct) and "Congratulations!" or "Sorry!"))
				if target then exports.anticheat:changeProtectedElementDataEx(target, "vct_level", ranks[3], true) end
		
			end
			if ranks[4] and ranks[4] ~= tonumber(user.scripter) then
				tail = tail.."scripter="..ranks[4]..","
				mysql:query_free("INSERT INTO staff_changelogs SET userid="..userid..", details="..details..", `by`="..getElementData(thePlayer, "account:id")..", team=4, from_rank="..user.scripter..", to_rank="..ranks[4])
				exports.global:sendMessageToStaff("[STAFF UPDATE] "..exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[4] > tonumber(user.scripter) and "promoted" or "demoted").." '"..user.username.."' from "..staffTitles[4][tonumber(user.scripter)].." to "..staffTitles[4][ranks[4]]..".", true)
				exports.announcement:makePlayerNotification(target or user.id, "Staff Rank Updated", exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[4] > tonumber(user.scripter) and "promoted" or "demoted").." you from "..staffTitles[4][tonumber(user.scripter)].." to "..staffTitles[4][ranks[4]]..". \n" .. (ranks[4] > tonumber(user.scripter) and "Congratulations!" or "Sorry!"))
				if target then exports.anticheat:changeProtectedElementDataEx(target, "scripter_level", ranks[4], true) end
		
			end
			if ranks[5] and ranks[5] ~= tonumber(user.mapper) then
				tail = tail.."mapper="..ranks[5]..","
				mysql:query_free("INSERT INTO staff_changelogs SET userid="..userid..", details="..details..", `by`="..getElementData(thePlayer, "account:id")..", team=5, from_rank="..user.mapper..", to_rank="..ranks[5])
				exports.global:sendMessageToStaff("[STAFF UPDATE] "..exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[5] > tonumber(user.mapper) and "promoted" or "demoted").." '"..user.username.."' from "..staffTitles[5][tonumber(user.mapper)].." to "..staffTitles[5][ranks[5]]..".", true)
				exports.announcement:makePlayerNotification(target or user.id, "Staff Rank Updated", exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[5] > tonumber(user.mapper) and "promoted" or "demoted").." you from "..staffTitles[5][tonumber(user.mapper)].." to "..staffTitles[5][ranks[5]]..". \n" .. (ranks[5] > tonumber(user.mapper) and "Congratulations!" or "Sorry!"))
				if target then exports.anticheat:changeProtectedElementDataEx(target, "mapper_level", ranks[5], true) end
		
			end
			if ranks[6] and ranks[6] ~= tonumber(user.fmt) then
				tail = tail.."fmt="..ranks[6]..","
				mysql:query_free("INSERT INTO staff_changelogs SET userid="..userid..", details="..details..", `by`="..getElementData(thePlayer, "account:id")..", team=6, from_rank="..user.fmt..", to_rank="..ranks[6])
				exports.global:sendMessageToStaff("[STAFF UPDATE] "..exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[6] > tonumber(user.fmt) and "promoted" or "demoted").." '"..user.username.."' from "..staffTitles[6][tonumber(user.fmt)].." to "..staffTitles[6][ranks[6]]..".", true)
				exports.announcement:makePlayerNotification(target or user.id, exports.global:getPlayerFullIdentity(thePlayer, 1, true).." has "..(ranks[6] > tonumber(user.fmt) and "promoted" or "demoted").." you from "..staffTitles[6][tonumber(user.fmt)].." to "..staffTitles[6][ranks[6]]..".", (ranks[6] > tonumber(user.fmt) and "Congratulations!" or "Sorry!"))
				if target then exports.anticheat:changeProtectedElementDataEx(target, "fmt_level", ranks[6], true) end
		
			end
			if tail ~= '' then
				tail = string.sub(tail, 1, string.len(tail)-1)
				if not dbExec(mysql:getConn(), dbPrepareString(mysql:getConn(), "UPDATE accounts SET " .. tail .. " WHERE id=" .. userid)) then
					outputChatBox("Internal Error!", thePlayer, 255, 0, 0)
					return false
				end
			end
			-- نداء مباشر بدل triggerEvent: الـ secure() بيرفض النداءات اللي مالهاش كلاينت
			getStaffInfo(thePlayer, user.username, "Staff rank for "..user.username.." has been set!")
		end
	end, {userid, staffTitles, target, ranks, details, thePlayer}, exports.mysql:getConn(), "SELECT id, username, admin, supporter, vct, scripter, mapper, fmt FROM accounts WHERE id=?", userid)

end
secure("staff:editStaff", editStaff, "none", 1000)

function makePlayerStaff(thePlayer, commandName, who, rank) --/ MAXIME
	if exports.integration:isPlayerSeniorAdmin(thePlayer) or exports.integration:isPlayerVehicleConsultant(thePlayer) or exports.integration:isPlayerLeadScripter(thePlayer) or exports.integration:isPlayerMappingTeamLeader(thePlayer) then
		if not (who) or not (tonumber(rank)) then
			outputChatBox("SYNTAX: /" .. commandName .. " [Player Partial Name/ID] [Staff Team ID] [Rank]", thePlayer, 255, 194, 14)
			outputChatBox("SYNTAX: /" .. commandName .. " [Exact Username] [Rank, -1 .. -4 = GMs, 1 .. 7 = Admins]", thePlayer, 255, 194, 14)
		else
			local targetPlayer, targetPlayerName = exports.global:findPlayerByPartialNick(thePlayer, who)
			local username = false
			local targetUsername = false
			local currentRank = false
			local adminID = false
			rank = tonumber(rank)

			if not targetPlayer then
				return false
			end

			targetUsername = getElementData(targetPlayer, "account:username")
			currentRank = getElementData(targetPlayer, "admin_level")
			adminID = getElementData(targetPlayer, "account:id")


			if (rank > 0) or (rank == -999999999) then
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_admin", 1, true)
			else
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_admin", 0, true)
			end

			if (rank < 0) then
				local gmrank = -rank
				outputChatBox("You set " .. targetPlayerName .. "'s GM rank to " .. tostring(gmrank) .. ".", thePlayer, 0, 255, 0)
				--outputChatBox(adminTitle .. " " .. username .. " set your GM rank to " .. gmrank .. ".", targetPlayer, 255, 194, 14)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "account:gmlevel", gmrank, false)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_supporter", 1, true)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "admin_level", 0, false)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_admin", 0, true)
			elseif rank == 0 then
				--outputChatBox(adminTitle .. " " .. username .. " removed your staff rank.", targetPlayer, 255, 194, 14)
				outputChatBox("You set " .. targetPlayerName .. " to Player.", thePlayer, 0, 255, 0)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "admin_level", 0, false)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_admin", 0, true)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "account:gmlevel", 0, false)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_supporter", 0, true)
			else
				--outputChatBox(adminTitle .. " " .. username .. " set your admin rank to " .. rank .. ".", targetPlayer, 255, 194, 14)
				outputChatBox("You set " .. targetPlayerName .. "'s Admin rank to " .. tostring(rank) .. ".", thePlayer, 0, 255, 0)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "admin_level", rank, false)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_admin", 1, true)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "account:gmlevel", 0, false)
				exports.anticheat:changeProtectedElementDataEx(targetPlayer, "duty_supporter", 0, true)
			end




			exports.logs:dbLog(thePlayer, 4, targetPlayer, "MAKEADMIN " .. rank)
			exports.global:updateNametagColor(targetPlayer)
		end
	end
end
--addCommandHandler("makestaff", makePlayerStaff, false, false)
