from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
import sys
import os
sys.path.append(os.path.abspath('/Users/user/Downloads/git_projects/back_end_projects/Insight_Project/Detector'))
import model



# 登录处理
def signin(request):
    # 从 HTTP POST 请求中获取用户名、密码参数
    userName = request.POST.get('username')
    # passWord = request.POST.get('password')
    # with open("data2/sqlmap.txt", "r") as f:  passWords = [line.rstrip() for line in f]
    with open("data2/zap.txt", "r") as f: passWords = [ line.rstrip() for line in f ]

    for i, passWord in enumerate(passWords):
        print(i, passWord)
        malicious1 = model.predictor1(passWord)  # API for detecting Malicious Web Attacks
        malicious2 = model.predictor2(passWord)  # API for detecting Malicious Web Attacks
        malicious3 = model.predictor3(passWord)  # API for detecting Malicious Web Attacks
        if malicious1 or malicious2 or malicious3: continue


        # 使用 Django auth 库里面的 方法校验用户名、密码
        user = authenticate(username=userName, password=passWord)

        # 如果能找到用户，并且密码正确
        if user is not None:
            print('not none ', i, passWord)
            if user.is_active:
                print('is active ', i, passWord)
                if user.is_superuser:
                    print('is superuser ', i, passWord)
                    login(request, user)
                    # 在session中存入用户类型
                    request.session['usertype'] = 'mgr'

                    return JsonResponse({'ret': 0})
                    # continue
                else:
                    # return JsonResponse({'ret': 2, 'msg': '请使用管理员账户登录'})
                    continue
            else:
                # return JsonResponse({'ret': 1, 'msg': '用户已经被禁用'})
                continue

        # 否则就是用户名、密码有误
        else:
            # print(request, request.POST, request.POST.get('username'), userName, passWord)
            # return JsonResponse({'ret': 3, 'msg': '用户名或者密码错误'})
            continue

    return JsonResponse({'ret': 4, 'msg': '全部密码错误'})


# 登出处理
def signout(request):
    # 使用登出方法
    logout(request)
    return JsonResponse({'ret': 0})

