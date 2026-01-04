import asyncio
import json
import ssl
import random
import requests
from flask import Flask, request, Response
import aiohttp
from datetime import datetime
import binascii

from xC4 import EnC_AEs, EnC_Uid, DeCode_PackEt, GeneRaTePk
import MajoRLoGinrEq_pb2, MajoRLoGinrEs_pb2
import search_account_req_pb2
import search_account_rsp_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# --- SPECIAL JSON HANDLER FOR UNICODE SUPPORT ---
def custom_jsonify(data, status=200):
    # ensure_ascii=False keeps the characters like 모 as they are
    js = json.dumps(data, ensure_ascii=False, indent=2)
    return Response(js, status=status, mimetype='application/json; charset=utf-8')
# ------------------------------------------------

# Encryption Keys
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Configuration
CONFIG = {
    "host": "clientbp.ggblueshark.com", 
    "uid": "4316459091",
    "password": "9X_JUBAYER__TD5LO__Y76IB",
    "user_agent": "GarenaMSDK/4.1.0P3(SM-A515F;Android 11;en-US;USA;)"
}

# --- INTERNAL LOGIN FUNCTIONS ---

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    return cipher.encrypt(padded_message)

async def GeNeRaTeAccEss(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": CONFIG["user_agent"],
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=data) as response:
            if response.status != 200: return None, None
            data = await response.json()
            return data.get("open_id"), data.get("access_token")

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28"
    major_login.system_hardware = "Handheld"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.login_by = 3
    major_login.reg_avatar = 1
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.login_open_id_type = 4
    major_login.release_channel = "android"
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    
    serialized = major_login.SerializeToString()
    return await encrypted_proto(serialized)

async def DoMajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': CONFIG["user_agent"],
        'Connection': "Keep-Alive",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB51"
    }
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
            return None

async def GetSessionToken():
    uid, password = CONFIG["uid"], CONFIG["password"]
    open_id, access_token = await GeNeRaTeAccEss(uid, password)
    if not open_id: return None
        
    encrypted_payload = await EncRypTMajoRLoGin(open_id, access_token)
    response_data = await DoMajorLogin(encrypted_payload)
    
    if response_data:
        proto = MajoRLoGinrEs_pb2.MajorLoginRes()
        proto.ParseFromString(response_data)
        return proto.token
    return None

# --- SEARCH FUNCTIONS ---

def encrypt_search_payload(data: bytes) -> bytes:
    padded_data = pad(data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(padded_data)

async def perform_search_by_name(nickname, token):
    headers = {
        "Host": CONFIG["host"],
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "User-Agent": CONFIG["user_agent"],
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB51",
        "Content-Type": "application/octet-stream"
    }

    req_proto = search_account_req_pb2.CSFuzzySearchAccountByNameReq()
    req_proto.nickname = nickname
    encrypted_data = encrypt_search_payload(req_proto.SerializeToString())
    url = f"https://{CONFIG['host']}/FuzzySearchAccountByName"
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=encrypted_data, headers=headers, ssl=False) as res:
            if res.status != 200: return None
            content = await res.read()
            
            response_proto = search_account_rsp_pb2.SCFuzzySearchAccountByNameRsp()
            response_proto.ParseFromString(content)
            
            results = []
            for acc in response_proto.accounts:
                results.append({"nickname": acc.nickname, "account_id": acc.account_id})
            return results

async def perform_search_by_uid(target_uid, token):
    try:
        encoded_uid = await EnC_Uid(target_uid, Tp='Uid')
        payload_hex = f"08{encoded_uid}1007"
        encrypted_hex = await EnC_AEs(payload_hex)
        data_bytes = bytes.fromhex(encrypted_hex)
        
        url = f"https://{CONFIG['host']}/GetPlayerPersonalShow"
        
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {token}',
            'Content-Length': str(len(data_bytes)),
            'User-Agent': CONFIG["user_agent"],
            'Host': CONFIG["host"],
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data_bytes, headers=headers, ssl=False) as response:
                if response.status != 200:
                    return {"error": f"Server returned {response.status}"}
                
                content = await response.read()
                packet_hex = content.hex()
                decoded_json_str = await DeCode_PackEt(packet_hex)
                if not decoded_json_str:
                    return {"error": "Failed to decode packet"}
                
                data_json = json.loads(decoded_json_str)
                try:
                    basic_data = data_json["1"]["data"]
                    
                    nickname = basic_data["3"]["data"]
                    level = basic_data["6"]["data"]
                    likes = basic_data["21"]["data"]
                    create_time = basic_data["44"]["data"]
                    
                    acc_create = datetime.fromtimestamp(create_time).strftime("%d/%m/%Y")
                    
                    return {
                        "uid": target_uid,
                        "nickname": nickname,
                        "level": level,
                        "likes": likes,
                        "created_at": acc_create
                    }
                except KeyError:
                    return {"error": "Player not found or data hidden"}
    except Exception as e:
        return {"error": str(e)}

# --- FLASK ROUTES ---

@app.route("/search", methods=["GET"])
def search_route():
    nickname = request.args.get("name")
    if not nickname: return custom_jsonify({"error": "Missing name"}, 400)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        token = loop.run_until_complete(GetSessionToken())
        if not token: return custom_jsonify({"error": "Login Failed"}, 500)
            
        results = loop.run_until_complete(perform_search_by_name(nickname, token))
        return custom_jsonify({"status": "success", "result": results})
    except Exception as e: return custom_jsonify({"error": str(e)}, 500)

@app.route("/uid", methods=["GET"])
def uid_route():
    target_uid = request.args.get("id")
    if not target_uid: return custom_jsonify({"error": "Missing id"}, 400)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        token = loop.run_until_complete(GetSessionToken())
        if not token: return custom_jsonify({"error": "Login Failed"}, 500)
            
        result = loop.run_until_complete(perform_search_by_uid(target_uid, token))
        return custom_jsonify({"status": "success", "result": result})
    except Exception as e: return custom_jsonify({"error": str(e)}, 500)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
