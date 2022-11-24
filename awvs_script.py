import json
import os
import sys
import threading
import time
from datetime import datetime

import requests
import urllib3
import yaml

urllib3.disable_warnings()


class Config:
    # 从配置文件中读取配置
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
        profile_id = cfg['profile_id'][cfg['scan_mode']]
        max_scan_count = cfg['max_scan_count']
        max_scan_time = cfg['max_scan_time']
    except Exception as e:
        print("读取配置文件出错，请检查配置是否规范")

    # 验证AWVS地址和API Token
    def check_api(self):
        try:
            resp = requests.get(self.awvs_url + '/api/v1/me/stats',
                                headers=self.headers,
                                timeout=10,
                                verify=False)
            if resp.status_code == 401:
                print("awvs认证失败，请检查您设置的api_key")
                sys.exit()
            result = json.loads(resp.content.decode())
            scans_running_count, scans_waiting_count = \
                result['scans_running_count'], result['scans_waiting_count']
            vuln_count = result['vuln_count']
            # 输出扫描基本信息
            print("正在扫描:", scans_running_count, "，等待扫描:", scans_waiting_count,
                  "，漏洞数量:", vuln_count)
        except Exception as e:
            print('初始化失败，请检查您设置的awvs_url是否正确\n', e)
            sys.exit()
        return scans_running_count


class Proxy:

    def __init__(self):
        self.cfg = Config()

    # 获取代理（如果proxy_enabled选项为False不进行抓取）
    def get_proxy(self):
        if not self.cfg.proxy_enabled:
            return "127.0.0.1", 8111
        while 1:
            try:
                proxy_str = requests.get(
                    self.cfg.proxy_pool +
                    "/get?type=HTTP&count=1&anonymity=all").content.decode()
                proxy_list = json.loads(proxy_str)
                proxy_ip = proxy_list['Ip']
                proxy_port = proxy_list['Port']
                anonymity = proxy_list['Anonymity']
                # 去掉透明代理
                if anonymity != "透明":
                    break
            except Exception as e:
                print("获取代理失败\n", e)
                sys.exit()
        return proxy_ip, proxy_port


class GetUrl:
    # 从url文件中读取url（url.txt或者./log/error_url.txt）
    @staticmethod
    def get_url_from_txt(count, txt, add_log):
        try:
            url_list = []
            if not os.path.getsize(txt):
                print("[*] {}中没有url，请将待检测的url写入txt文件".format(txt))
                sys.exit()

            # 把添加成功的url写入add_log.txt或者readd_log.txt
            with open(txt, 'r') as f:
                for url in f.readlines()[0:count]:
                    with open(add_log, 'a') as log:
                        log.write(url)

                    # url预处理
                    if 'http' not in url[0:7]:
                        url = "http://" + url
                    url = url.strip().rstrip('/')
                    url_list.append(url)
        except Exception as e:
            print("[*] 请确认{}的位置是否正确\n".format(txt), e)
            sys.exit()
        return url_list


class Target:

    def __init__(self):
        self.cfg = Config()

    # 根据target_id获取单个目标的信息
    def get_target(self, target_id):
        try:
            r = requests.get(self.cfg.awvs_url +
                             "/api/v1/targets/{}".format(target_id),
                             headers=self.cfg.headers,
                             timeout=10,
                             verify=False)
            target = json.loads(r.content.decode())
            return target
        except Exception as e:
            print("获取目标失败\n", e)

    # 获取扫描器中的所有目标的信息
    def get_targets(self):
        try:
            resp = requests.get(self.cfg.awvs_url + "/api/v1/targets",
                                headers=self.cfg.headers,
                                timeout=10,
                                verify=False)
            result = json.loads(resp.content.decode())
            return result
        except Exception as e:
            print("获取目标失败\n", e)

    # 批量添加目标到扫描器，并会从url文件中删除已经添加成功的url
    def add_targets(self, txt, add_log):
        count = input("[*] 请输入要添加的目标数量(留空则添加{}中全部url)：".format(txt)) or None
        if count is not None:
            count = int(count)
        url_list = GetUrl().get_url_from_txt(count, txt, add_log)
        target_id_list = []
        flag = None
        for url in url_list:
            try:
                data = {
                    "address": url,
                    "description": self.cfg.scan_label,
                    "criticality": "10"
                }
                response = requests.post(self.cfg.awvs_url + "/api/v1/targets",
                                         data=json.dumps(data),
                                         headers=self.cfg.headers,
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
                print("[*] 添加目标失败\n", e)

        # 从存放url的文件中删除已经添加成功的url
        if flag:
            try:
                with open(txt, 'r') as f_r:
                    lines = f_r.readlines()[count:]
                    with open(txt, 'w') as f_w:
                        if count is None:
                            lines = {}
                        f_w.writelines(lines)
            except Exception as e:
                print("[*] 去除txt中已添加到扫描器的url时出错\n", e)
        self.configuration(target_id_list, self.cfg.profile_id)
        return target_id_list

    # 配置已添加到扫描器的目标的扫描参数，添加目标时会调用该方法
    def configuration(self, target_id_list, default_scanning_profile_id):
        for target_id in target_id_list:
            configuration_url = self.cfg.awvs_url + \
                                "/api/v1/targets/{}/configuration".format(target_id)

            proxy_ip, proxy_port = Proxy().get_proxy()
            try:
                data = {
                    "scan_speed": self.cfg.scan_speed,
                    "default_scanning_profile_id": default_scanning_profile_id,
                    "proxy": {
                        "enabled": self.cfg.proxy_enabled,
                        "protocol": "http",
                        "address": proxy_ip,
                        "port": proxy_port
                    }
                }
                requests.patch(url=configuration_url,
                               data=json.dumps(data),
                               headers=self.cfg.headers,
                               timeout=30,
                               verify=False)
            except Exception as e:
                print(e)

    # 根据传入的target_id批量删除目标
    def del_target(self, target_id, target_address):
        try:
            r = requests.delete(self.cfg.awvs_url + "/api/v1/targets/" +
                                target_id,
                                headers=self.cfg.headers,
                                timeout=30,
                                verify=False)
            return r.status_code
        except Exception as e:
            print("删除目标{}时发送错误\n".format(target_address), e)

    # 删除扫描器中的所有目标，同时会删除扫描任务
    def del_targets(self):
        targets_info = self.get_targets()
        targets_count = targets_info['pagination']['count']
        targets = targets_info['targets']
        if targets_count == 0:
            print("[*] 已删除所有目标，当前目标列表为空")
        print("[*] 当前目标数量为{}".format(targets_count))
        for target in targets:
            target_id = target['target_id']
            target_address = target['address']
            status_code = self.del_target(target_id, target_address)
            if status_code == 204:
                print(target_address, " 删除目标成功")


class Scan:

    def __init__(self):
        self.cfg = Config()

    # 根据传入的target_id批量添加扫描任务
    def scan_targets(self, target_id_list):
        for target_id in target_id_list:
            data = {
                "target_id": target_id,
                "profile_id": self.cfg.profile_id,
                "incremental": False,
                "schedule": {
                    "disable": False,
                    "start_date": None,
                    "time_sensitive": False
                }
            }
            try:
                r = requests.post(self.cfg.awvs_url + "/api/v1/scans",
                                  data=json.dumps(data),
                                  headers=self.cfg.headers,
                                  timeout=30,
                                  verify=False)
                if r.status_code == 201:
                    target = Target().get_target(target_id)
                    target_address = target['address']
                    print(target_address, " 添加扫描任务成功")
            except Exception as e:
                print("[*] 添加扫描任务失败\n", e)

    # 对扫描器内已有的目标进行扫描，同样可以控制扫描的数量
    def scan_exist_targets(self):
        not_scan_target_list = []
        targets_info = Target().get_targets()
        targets = targets_info['targets']
        for target in targets:
            last_scan_id = target['last_scan_id']
            target_id = target['target_id']
            if last_scan_id is None:
                not_scan_target_list.append(target_id)
        print("未扫描的目标数量为:", len(not_scan_target_list))
        count = input("请输入要开始扫描的目标个数(留空则开始扫描所有未扫描目标):") or None
        if count is not None:
            count = int(count)
        target_id_list = not_scan_target_list[0:count]
        self.scan_targets(target_id_list)

    # 获取扫描器内所有扫描任务的信息
    def get_scans(self):
        try:
            resp = requests.get(self.cfg.awvs_url + "/api/v1/scans",
                                headers=self.cfg.headers,
                                timeout=30,
                                verify=False)
            scan_list = json.loads(resp.content.decode())
            return scan_list
        except Exception as e:
            print(e)

    # 中止扫描器内所有正在扫描的任务
    def abort_scans(self):
        scan_list = self.get_scans()['scans']
        for scan in scan_list:
            scan_id = scan['scan_id']
            scan_status = scan['current_session']['status']
            target_address = scan['target']['address']
            if scan_status == "processing":
                try:
                    resp = requests.post(
                        self.cfg.awvs_url +
                        "/api/v1/scans/{}/abort".format(scan_id),
                        headers=self.cfg.headers,
                        timeout=30,
                        verify=False)
                    if resp.status_code == 204:
                        print(target_address, " 扫描任务已中止")
                except Exception as e:
                    print("[*] 中止扫描任务时出现错误\n", e)

    # 获取扫描器内扫描失败的url，保存到'./log/error_url.txt中'，同时会删除扫描器内扫描失败的url
    def get_error_scans(self):
        print("[*] 该操作会删除扫描器中扫描失败的目标，并将扫描失败的URL保存至log文件夹下")
        confirm = input("[*] 是否要删除扫描器中扫描失败的目标(y/n)：")
        if confirm != "y":
            print("[*] 您已取消该操作")
            sys.exit()
        scan_list = self.get_scans()['scans']
        try:
            with open("./log/error_url.txt", 'a') as f:
                for scan in scan_list:
                    if scan['current_session']['event_level'] == 2:
                        error_target_id = scan['target_id']
                        error_url = scan['target']['address']
                        f.write(error_url + '\n')
                        # 删除扫描器中扫描失败的url
                        status_code = Target().del_target(
                            error_target_id, error_url)
                        if status_code == 204:
                            print(error_url, " 扫描失败，已从扫描器中删除目标")
            print("[*] 扫描失败的URL已保存至log文件夹下的error_url.txt中")
        except Exception as e:
            print("[*] 获取扫描失败的URL时出现错误\n", e)

    # 将‘./log/error_url.txt’中的url重新添加到扫描器并开始扫描，同样可以控制扫描的数量
    def rescan_error_scans(self):
        confirm = input("[*] 是否已经执行【获取扫描失败的目标】(y/n)：")
        if confirm != "y":
            print("[*] 已取消操作")
            sys.exit()
        print("[*] 正在尝试对扫描失败的目标进行重新扫描")
        self.scan_targets(Target().add_targets(txt="./log/error_url.txt",
                                               add_log="./log/readd_log.txt"))


class Monitor:

    def __init__(self):
        self.cfg = Config()

    # 根据传入的scan_id中止扫描任务
    def abort_scans(self, scan_dict):
        for key in scan_dict:
            try:
                resp = requests.post(self.cfg.awvs_url +
                                     "/api/v1/scans/{}/abort".format(key),
                                     headers=self.cfg.headers,
                                     timeout=30,
                                     verify=False)
                if resp.status_code == 204:
                    print("\n", scan_dict[key], " 扫描任务超过两小时，已中止扫描任务\n")
            except Exception as e:
                print("[*] 中止扫描任务时出现错误\n", e)

    # 将扫描器中已有的目标添加到扫描任务
    def add_scans(self, count):
        not_scan_target_list = []
        targets_info = Target().get_targets()
        targets = targets_info['targets']
        for target in targets:
            last_scan_id = target['last_scan_id']
            target_id = target['target_id']
            if last_scan_id is None:
                not_scan_target_list.append(target_id)
        print("未扫描的目标数量为:", len(not_scan_target_list))
        target_id_list = not_scan_target_list[0:count]
        if len(not_scan_target_list) > 0:
            Scan().scan_targets(target_id_list)
        return target_id_list

    # 对比所有正在扫描的任务的开始时间和当前时间，返回超过最大扫描时间的scan_id
    def time_diff(self):
        scans = Scan().get_scans()['scans']
        scan_dict = {}
        for scan in scans:
            try:
                status = scan['current_session']['status']
                scan_id = scan['scan_id']
                target_address = scan['target']['address']
                if status == 'processing':
                    start_time = scan['current_session']['start_date'][0:-6]
                    UTC_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'
                    start_time = datetime.strptime(start_time, UTC_FORMAT)
                    now_time = datetime.now()
                    is_time_out = int(
                        str(now_time - start_time).split(":")
                        [0]) > self.cfg.max_scan_time - 1
                    if is_time_out is True:
                        scan_dict[scan_id] = target_address
            except Exception as e:
                print("获取时间差失败", e)
        return scan_dict

    # 检查当前正在进行的扫描任务的数量，未达到最大扫描任务数量时，向扫描器中添加扫描任务
    def add_to_limit(self):
        count = Config().check_api()
        if count < self.cfg.max_scan_count:
            diff_count = self.cfg.max_scan_count - count
            target_id_list = Monitor().add_scans(diff_count)
            print("[*] 已向扫描器添加{}个扫描任务\n".format(len(target_id_list)))


def main():
    Config().check_api()

    usage = """[*] 请选择要进行的操作：
1、批量添加目标，不进行扫描
2、批量添加目标并开始扫描
3、对扫描器内已有目标进行扫描
4、中止所有扫描任务
5、获取扫描失败的目标
6、对扫描失败的目标重新扫描
7、删除所有目标和扫描任务
"""

    print(usage)
    selection = str(input("请输入数字："))

    if selection == "1":
        Target().add_targets(txt="url.txt", add_log="./log/add_log.txt")

    elif selection == "2":
        Scan().scan_targets(Target().add_targets(txt="url.txt",
                                                 add_log="./log/add_log.txt"))

    elif selection == "3":
        Scan().scan_exist_targets()

    elif selection == "4":
        Scan().abort_scans()

    elif selection == "5":
        Scan().get_error_scans()

    elif selection == "6":
        Scan().rescan_error_scans()

    elif selection == "7":
        Target().del_targets()

    else:
        print("输入的内容有误")


# 监控是否有超过最大扫描时间的任务
def monitor_time():
    try:
        while 1:
            time.sleep(600)
            scan_dict = Monitor().time_diff()
            if len(scan_dict) != 0:
                Monitor().abort_scans(scan_dict)
    except KeyboardInterrupt:
        print("\nApplication exit!")


# 监控是否达到最大扫描任务数量，未达到则向扫描器添加扫描任务
def monitor_count():
    try:
        while 1:
            Monitor().add_to_limit()
            time.sleep(180)
    except KeyboardInterrupt:
        print("\nApplication exit!")


if __name__ == '__main__':
    try:
        if len(sys.argv) == 1:
            main()
        elif len(sys.argv) == 2 and sys.argv[1] == 'monitor':
            threads = []
            t1 = threading.Thread(target=monitor_time)
            t2 = threading.Thread(target=monitor_count)
            threads.append(t1)
            threads.append(t2)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        else:
            print("""1、执行python3 awvs_script.py使用基本模式
2、执行python3 awvs_script.py monitor使用监控模式（Linux可执行"nohup python3 -u awvs_script.py monitor &"让脚本后台运行）"""
                  )
    except Exception as e:
        print(e)
