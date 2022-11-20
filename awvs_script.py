import json
import os
import sys
import requests
import urllib3
import yaml

urllib3.disable_warnings()

try:
    with open('config.yaml', 'r', encoding='utf-8') as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)
    proxy_pool = cfg['proxy_pool']
    awvs_url = cfg['awvs_url']
    api_key = cfg['api_key']
    headers = {'Content-Type': 'application/json', "X-Auth": api_key}
    scan_label = cfg['scan_label']
    scan_speed = cfg['scan_speed']
    proxy_enabled = cfg['proxy_enabled']
    profile_id = cfg['profile_id']
except Exception as e:
    print("读取配置文件出错，请检查配置是否规范")


def check_api():
    try:
        resp = requests.get(awvs_url + '/api/v1/me/stats',
                            headers=headers,
                            timeout=10,
                            verify=False)
        if resp.status_code == 401:
            print("awvs认证失败，请检查您设置的api_key")
            sys.exit()
        result = json.loads(resp.content.decode())
        scans_running_count, scans_waiting_count = result[
            'scans_running_count'], result['scans_waiting_count']
        vuln_count = result['vuln_count']
        print("正在扫描:", scans_running_count, "，等待扫描:", scans_waiting_count,
              "，漏洞数量:", vuln_count)
    except Exception as e:
        print('初始化失败，请检查您设置的awvs_url是否正确\n', e)
        sys.exit()


def get_proxy():
    while 1:
        try:
            proxy_str = requests.get(
                proxy_pool +
                "/get?type=HTTP&count=1&anonymity=all").content.decode()
            proxy_lsit = json.loads(proxy_str)
            proxy_ip = proxy_lsit['Ip']
            proxy_port = proxy_lsit['Port']
            anonymity = proxy_lsit['Anonymity']
            if anonymity != "透明":
                break
        except Exception as e:
            print("获取代理失败", e)
            sys.exit()
    return proxy_ip, proxy_port


def get_url_from_txt(count, txt='url.txt', add_log='./log/add_log.txt'):
    url_list = []
    try:
        if not os.path.getsize(txt):
            print("[*] {}中没有url，请将待检测的url写入txt文件".format(txt))
            sys.exit()

        with open(txt, 'r') as f:
            for url in f.readlines()[0:count]:
                with open(add_log, 'a') as log:
                    log.write(url)

                if 'http' not in url[0:7]:
                    url = "http://" + url
                url = url.strip().rstrip('/')
                url_list.append(url)

    except Exception as e:
        print("[*] 请确认{}的位置是否正确".format(txt), e)
        sys.exit()
    return url_list


def add_targets(txt='url.txt', add_log='./log/add_log.txt'):
    count = input("[*] 请输入要添加的目标数量(留空则添加txt中全部url)：") or None
    if count != None:
        count = int(count)
    url_list = get_url_from_txt(count, txt, add_log)
    flag = None
    target_id_list = []
    for url in url_list:
        try:
            data = {
                "address": url,
                "description": scan_label,
                "criticality": "10"
            }
            response = requests.post(awvs_url + "/api/v1/targets",
                                     data=json.dumps(data),
                                     headers=headers,
                                     timeout=30,
                                     verify=False)
            result = json.loads(response.content)
            target_id = result['target_id']
            target_address = result['address']
            target_id_list.append(target_id)
            if response.status_code == 201:
                print(target_address, " 目标添加成功")
                flag = True
        except Exception as e:
            flag = False
            print("[*] 添加目标失败", e)

    if flag:
        try:
            with open(txt, 'r') as f_r:
                lines = f_r.readlines()[count:]
                with open(txt, 'w') as f_w:
                    if count == None:
                        lines = {}
                    f_w.writelines(lines)
        except Exception as e:
            print("[*] 去除txt中已添加到扫描器的url时出错", e)

    configuration(target_id_list, profile_id)
    return target_id_list


def configuration(target_id_list, default_scanning_profile_id):
    for target_id in target_id_list:
        configuration_url = awvs_url + \
            "/api/v1/targets/{}/configuration".format(target_id)

        proxy_ip, proxy_port = get_proxy()
        try:
            data = {
                "scan_speed": scan_speed,
                "default_scanning_profile_id": default_scanning_profile_id,
                "proxy": {
                    "enabled": proxy_enabled,
                    "protocol": "http",
                    "address": proxy_ip,
                    "port": proxy_port
                }
            }
            requests.patch(url=configuration_url,
                           data=json.dumps(data),
                           headers=headers,
                           timeout=30,
                           verify=False)
        except Exception as e:
            print(e)


def scan_targets(txt='url.txt', add_log='./log/add_log.txt'):
    scan_id_list = []
    target_id_list = add_targets(txt, add_log)
    for target_id in target_id_list:
        data = {
            "target_id": target_id,
            "profile_id": profile_id,
            "incremental": False,
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False
            }
        }
        try:
            resp = requests.post(awvs_url + "/api/v1/scans",
                                 data=json.dumps(data),
                                 headers=headers,
                                 timeout=30,
                                 verify=False)
            result = json.loads(resp.content.decode())
            scan_id = result['scan_id']
            scan_id_list.append(scan_id)
        except Exception as e:
            print("[*] 添加扫描任务失败", e)
    return scan_id_list


def get_scans():
    try:
        resp = requests.get(awvs_url + "/api/v1/scans",
                            headers=headers,
                            timeout=30,
                            verify=False)
        scan_list = json.loads(resp.content.decode())
    except Exception as e:
        print(e)
    return scan_list


def get_error_scans():
    scan_list = get_scans()['scans']
    error_target_id_list = []
    try:
        with open("./log/error_url.txt", 'w') as f:
            for scan in scan_list:
                if scan['current_session']['event_level'] == 2:
                    error_target_id = scan['target_id']
                    error_url = scan['target']['address']
                    error_target_id_list.append(error_target_id)
                    f.write(error_url + '\n')
                    print(error_url, " 扫描失败")
        print("\n[*] 扫描失败的URL已保存至log文件夹下的error_url.txt中")
    except Exception as e:
        print("[*] 获取扫描失败的URL时出现错误", e)
    return error_target_id_list


def abort_scans():
    scan_list = get_scans()['scans']
    for scan in scan_list:
        scan_id = scan['scan_id']
        scan_status = scan['current_session']['status']
        target_address = scan['target']['address']
        if scan_status == "processing":
            try:
                resp = requests.post(awvs_url +
                                     "/api/v1/scans/{}/abort".format(scan_id),
                                     headers=headers,
                                     timeout=30,
                                     verify=False)
                if resp.status_code == 204:
                    print(target_address, " 扫描任务已中止")
            except Exception as e:
                print("[*] 中止扫描任务时出现错误", e)


def del_targets():
    try:
        resp = requests.get(awvs_url + "/api/v1/targets",
                            headers=headers,
                            timeout=30,
                            verify=False)
        result = json.loads(resp.content.decode())
        targets_count = result['pagination']['count']
        targets = result['targets']

        if targets_count == 0:
            print("[*] 已删除所有目标，当前目标列表为空")
        for target in targets:
            target_id = target['target_id']
            target_address = target['address']
            try:
                del_resp = requests.delete(awvs_url + "/api/v1/targets/" +
                                           target_id,
                                           headers=headers,
                                           timeout=30,
                                           verify=False)
                if del_resp.status_code == 204:
                    print(target_address, " 删除目标成功")
            except Exception as e:
                print(target_address, e)
    except Exception as e:
        print("[*] 删除目标时出现错误", e)


def rescan_error_scans():
    print("[*] 该操作会先删除扫描器中扫描失败的目标，请先执行【获取扫描失败的目标】")
    confirm = input("[*] 是否要删除扫描器中扫描失败的目标(y/n)：")
    if confirm != "y":
        print("请先执行【获取扫描失败的目标】")
        sys.exit()
    scan_list = get_scans()['scans']
    for scan in scan_list:
        if scan['current_session']['event_level'] == 2:
            error_target_id = scan['target_id']
            error_url = scan['target']['address']
            try:
                resp = requests.delete(awvs_url + "/api/v1/targets/" +
                                       error_target_id,
                                       headers=headers,
                                       timeout=30,
                                       verify=False)
                if resp.status_code == 204:
                    print(error_url, " 删除目标成功")
            except Exception as e:
                print("[*] 删除目标时出现错误:", e)
    print("\n[*] 正在尝试对扫描失败的目标进行重新扫描")
    scan_targets(txt="./log/error_url.txt", add_log="./log/readd_log.txt")


if __name__ == '__main__':

    check_api()

    help = """[*] 请选择要进行的操作：
1、批量添加目标，不进行扫描
2、批量添加目标并开始扫描
3、获取扫描失败的目标
4、中止所有扫描任务
5、删除所有目标和扫描任务
6、对扫描失败的目标重新扫描
"""

    print(help)
    selection = str(input("请输入数字："))

    if selection == "1":
        add_targets()

    elif selection == "2":
        scan_targets()

    elif selection == "3":
        get_error_scans()

    elif selection == "4":
        abort_scans()

    elif selection == "5":
        del_targets()

    elif selection == "6":
        rescan_error_scans()

    else:
        print("输入的内容有误")
