# -*- coding: utf-8 -*-
# @Time    : 2020/8/20 15:55
# @Author  : Min
# @Email   : xgmin
# @File    : harbor_api.py
# @Software: PyCharm


import json
import urllib3
import requests
import time,logging

urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO)

class Harborapi(object):
    def __init__(self,zone):
        '''
        init the request
        :param url: url address or doma
        :param username:
        :param passwd:
        :param protect:
        '''
        if zone == "test":
            self.url = 'harbor0.com'
            self.username = 'admin'
            self.passwd ='Harbor12345'
        if zone == "prod":
            self.url = 'harborprod.com'
            self.username = 'admin'
            self.passwd ='Harbor12345'
        self.protocol = 'https'
        self.session_id_key = "sid"
        # self.csrf = '__csrf'
        # self.gorilla_csrf = '_gorilla_csrf'
        self.headers =  {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0', \
            'Content-Type':'application/json'
        }
        self.cookie=self.login_get_csrf_tokern()
        self.csrf_Token = self.cookie.get('__csrf')
        self.session_id= self.login_get_session_id()

    def login_get_csrf_tokern(self):
        '''
        通过log_out获取到csrf_token
        :return:
        '''
        url = "%s://%s/c/log_out"%(self.protocol, self.url)
        response = requests.get(url,headers=self.headers)
        dick = response.cookies.get_dict()
        return dick

    def login_get_session_id(self):
        '''
        by the login api/v2.0 to get the session of id
        :return:
        '''
        harbor_version_url = "%s://%s/api/v2.0/systeminfo"%(self.protocol, self.url)
        header_dict = {
            'Accept':'application/json, text/plain, */*',
            'Connection':'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Harbor-CSRF-Token' : self.csrf_Token
        }
        data_dict = {
            "principal": self.username,
            "password": self.passwd
        }
        v_req_handle = requests.get(harbor_version_url, verify=False)
        #print(v_req_handle.json())

        self.harbor_version = v_req_handle.json()["harbor_version"]
        if self.harbor_version.startswith("v2.0"):
            req_url = "%s://%s/c/login" % (self.protocol, self.url)
            self.session_id_key = "sid"
        else:
            raise ConnectionError("the %s version is not to supply!"%self.harbor_version)
        req_handle = requests.post(req_url, data=data_dict, headers=header_dict, verify=False, cookies=self.cookie)
        #print(req_handle.status_code,req_handle.text)


        if 200 == req_handle.status_code:
            self.session_id = req_handle.cookies.get(self.session_id_key)
            self.cookie['sid'] = self.session_id
            return self.session_id
        else:
            raise Exception("login error,please check your account info!"+ self.harbor_version)


    #def logout(self):
    #    requests.get('%s://%s/c/logout' %(self.protocol, self.url),
    #                 cookies={self.session_id_key: self.session_id})
    #    raise Exception("successfully logout")

    def get_statistics(self):
        '''
        获取harbor项目等统计信息
        :return:
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        result = None
        path = '%s://%s/api/v2.0/statistics' % (self.protocol, self.url)
        response = requests.get(path,cookies=cookie)
        if response.status_code == 200:
            result = response.json()
            logging.debug("Successfully get statistics: {}".format(result))
        else:
            logging.error("Fail to get statistics result")
        return result

    def get_logs(self,project_name):
        '''
        通过项目名称获取此项目最近操作日志
        :param project_name:
        :return:
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        result = None
        path = '%s://%s/api/v2.0/projects/%s/logs?page=1&page_size=100' % (self.protocol, self.url,project_name)
        response = requests.get(path,cookies=cookie)
        if response.status_code == 200:
            result = response.json()
            logging.debug("Successfully get logs")
        else:
            logging.error("Fail to get logs and response code: {}".format(
                response.status_code))
        return result

    def cheack_project_exist(self,project_name):
        '''
        通过head方法检测project是否存在，存在返回True，否则False
        :param project_name:
        :return:
        '''
        header_dict = {
            'Accept':'application/json, text/plain, */*',
            'Connection':'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Harbor-CSRF-Token' : self.csrf_Token
        }
        path = '%s://%s/api/v2.0/projects?project_name=%s' %(self.protocol,self.url,project_name)
        print(path)
        cookie = self.cookie
        cookie['sid'] = self.session_id
        result = False
        response = requests.head(path,cookies=cookie,headers=header_dict)
        #print(response.status_code)
        if response.status_code == 200 or response.status_code == 500:
            #print("this project is exist!")
            return True
        elif response.status_code == 404:
            #print("this project not exist!")
            return False
        else:
            raise Exception("Failed to get the project info!")


    def create_project(self, project_name,limit=None):
        '''
        创建项目，并限额，如不输入配额默认为无限制
        :param project_name:
        :param limit:
        :return:
        '''
        default_limit = -1
        limit = int(limit)
        project_limit = limit*1024*1024*1024
        cookie = self.cookie
        cookie['sid'] = self.session_id
        header_dict = {
            'content-type': 'application/json; charset=utf-8 ',
            'Connection':'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
            'Content-Type': 'application/json',
            'X-Harbor-CSRF-Token' : self.csrf_Token
        }
        result = False
        path = '%s://%s/api/v2.0/projects' % (self.protocol, self.url)
        S = project_limit or default_limit
        dict_metadata = {
            #"count_limit":0,
            "project_name":project_name,
            "storage_limit":S,
            "metadata":{"public":"False"},
        }
        #{self.session_id_key: self.session_id}
        request_body = json.dumps(dict_metadata)
        #print(request_body)
        #print(type(request_body))
        if self.cheack_project_exist(project_name) == False:
            response = requests.post(path,cookies=cookie,data=request_body, headers = header_dict )
        #print(response.text)
            if response.status_code == 201 or response.status_code == 500:
                # TODO: the response return 500 sometimes
                result = True
                logging.debug(
                    "Successfully create project with project name: {}".format(
                        project_name))
            else:
                logging.error(
                    "Fail to create project with project name: {}, response code: {}".format(
                        project_name, response.status_code))
            return result
        else:
            return False

    def search_user(self,username):
        '''
        搜索用户是否存在，不存在通过返回None判断返回False。
        存在返回用户ID
        :param username:
        :return:
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        result = False
        path = '%s://%s/api/v2.0/users/search?username=%s' % (self.protocol, self.url,username)
        response = requests.get(path,cookies=cookie)
        #print(response.text)
        if 200 == response.status_code:
            if response.json() == None:
                #print("this user is not exsit!")
                return False
            else:
                userresp = response.json()
                userid = userresp[0]["user_id"]
                return userid
        else:
            raise Exception("Failed to get the project info!")


    def get_project(self):
        '''
        获取所有项目信息
        :return:
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        result = False
        path = '%s://%s/api/v2.0/projects' % (self.protocol, self.url)
        response = requests.get(path,cookies=cookie)
        if 200 == response.status_code:
            return response.json()
        else:
            raise Exception("Failed to get the project info!")

    def get_user_id(self,username):
        '''
        根据用户名获取用户ID
        :param username:
        :return:
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        path = '%s://%s/api/v2.0/users/search?username=%s' % (self.protocol, self.url,username)
        response = requests.get(path,cookies=cookie)
        user_value = response.json()
        user_id = user_value[0]['user_id']
        return user_id

    def search_pro_reponse_chart(self,name):
        '''
        目前主要获取项目ID，还可以获取chart和repositories
        :param name:
        :return:
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        path = '%s://%s/api/v2.0/search?q=%s' % (self.protocol, self.url,name)
        response = requests.get(path,cookies=cookie)
        pro_value = response.json()['project']
        repo_value = response.json()['repository']
        chart_value = response.json()['chart']
        pro_id = pro_value[0]['project_id']
        return pro_id

    def create_user(self,email,password,username):
        '''
        创建用户，非管理员，创建前先检测用户是否存在
        :param email:
        :param password:
        :param project_name:
        :param username:
        :return:
        "username": username,
        "password": password,
        "realname": username,
        "deleted": "false",
        "creation_time": "string",
        "admin_role_in_auth": "false",
        "role_id": 1,
        "sysadmin_flag": "false",
        "role_name": "string",
        "reset_uuid": "string",
        "Salt": "string",
        "email": "string"
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        header_dict = {
            'content-type': 'application/json; charset=utf-8 ',
            'Connection':'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
            'Content-Type': 'application/json',
            'X-Harbor-CSRF-Token' : self.csrf_Token
        }
        result = False
        path = '%s://%s/api/v2.0/users' % (self.protocol, self.url)
        #password = passsword_code()

        dict_metadata = {
            #"count_limit":0,
            "email":email,
            "password":password,
            "realname":username,
            "username":username,
            #"role_id": 2,
            #"sysadmin_flag":"false"
        }
        request_body = json.dumps(dict_metadata)
        print(request_body)
        if self.search_user(username) == False:
            response = requests.post(path,cookies=cookie,data=request_body, headers = header_dict )
            # print(response.text)
            # print(response.status_code)
            if response.status_code == 201 or response.status_code == 500:
                # TODO: the response return 500 sometimes
                result = True
                logging.debug(
                    "Successfully create user with username: {}".format(
                        username))
            else:
                logging.error(
                    "Fail to create user with username: {}, response code: {}".format(
                        username, response.status_code))
            return result
        else:
            pass

    def create_project_member(self,username,project_name):
        '''
        变更项目成员，目前先增加账号为管理员
        role-id
        0:admin
        1:项目管理员
        2:开发人员
        3:访客
        4:维护人员
        5:受限访客
        '''
        cookie = self.cookie
        cookie['sid'] = self.session_id
        header_dict = {
            'content-type': 'application/json; charset=utf-8 ',
            'Connection':'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
            'Content-Type': 'application/json',
            'X-Harbor-CSRF-Token' : self.csrf_Token
        }
        project_id = self.search_pro_reponse_chart(project_name)
        path = '%s://%s/api/v2.0/projects/%s/members' % (self.protocol, self.url,project_id)
        dict_metadata = {
            "role_id":1,
            "member_user":{
                "username":username
            }
        }
        request_body = json.dumps(dict_metadata)
        if self.search_user(username) is not None:
            response = requests.post(path,cookies=cookie,data=request_body, headers = header_dict )
            #print(response.status_code)
            if response.status_code == 201 or response.status_code == 500:
                # TODO: the response return 500 sometimes
                result = True
                logging.debug(
                    "Successfully create user:{} , members in project: {}".format(
                        username,project_name))
            elif response.status_code == 409:
                result = False
                logging.error(" user group with same group name already exist! ")
            else:
                result = False
                logging.error(
                    "Fail to create user:{} , members in project: {}".format(
                        username, project_name))
            return result
        else:
            pass

    def change_project_quotas(self,project_name,size):
        cookie = self.cookie
        cookie['sid'] = self.session_id
        header_dict = {
            'content-type': 'application/json; charset=utf-8 ',
            'Connection':'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
            'Content-Type': 'application/json',
            'X-Harbor-CSRF-Token' : self.csrf_Token
        }
        pro_id = self.search_pro_reponse_chart(project_name)
        size = int(size)
        totalsize = size*1024*1024*1024
        path = '%s://%s/api/v2.0/quotas/%s' % (self.protocol, self.url,pro_id)
        dict_metadata = {
            #"count_limit":0,
            "hard":{
               "storage":totalsize
            }
        }
        request_body = json.dumps(dict_metadata)
        #https://harbor0.sinosig.com/api/v2.0/quotas/9
        response = requests.put(path,cookies=cookie,data=request_body, headers = header_dict )
        if response.status_code == 200 or response.status_code == 500:
            # TODO: the response return 500 sometimes
            result = True
            logging.debug(
                "Successfully change project:{} , size is: {}".format(
                    project_name,size))
        else:
            result = False
            logging.error(
                "Fail to change project: {}".format(
                  project_name))
        return result


    def change_user_passwd(self,username,password):
        cookie = self.cookie
        cookie['sid'] = self.session_id
        header_dict = {
            'content-type': 'application/json; charset=utf-8 ',
            'Connection':'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
            'Content-Type': 'application/json',
            'X-Harbor-CSRF-Token' : self.csrf_Token
        }
        if self.search_user(username) is not None:
            user_id = self.get_user_id(username)
            path = '%s://%s/api/v2.0/users/%s/password' % (self.protocol, self.url,user_id)
            dict_metadata = {
                'new_password': password,
                'old_password': password
            }
            request_body = json.dumps(dict_metadata)
            response = requests.put(path,cookies=cookie,data=request_body, headers = header_dict )
            if response.status_code == 200 or response.status_code == 500:
                # TODO: the response return 500 sometimes
                result = True
                logging.debug(
                    "Successfully change user :{}  password".format(
                        username))
            else:
                result = False
                logging.error(
                    "Fail to change user:{} password".format(
                      username))
            return result
        else:
            logging.error(
                "can not find this user :{}".format(username)
            )
            return False





