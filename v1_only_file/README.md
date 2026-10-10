# 局域网文件中转站

一个只使用 Python 标准库的本地文件暂存服务。支持 Linux 和 macOS，无数据库服务、Node 或第三方包依赖。

## 启动

需要 Python 3.10 或更新版本。

```bash
python3 server.py
```

终端会列出可访问地址。同一局域网设备打开其中的局域网 IP 地址，例如 `http://192.168.1.20:8080`。

第一次使用某个用户名登录时会自动创建账户；之后需要使用同一密码。每个账户只能看到和操作自己的文件。

### 使用用户名密码白名单

复制示例文件并直接编辑：

```bash
cp users.example.txt users.txt
python3 server.py --users users.txt
```

`users.txt` 使用 UTF-8 编码，每行一个账户：

```text
# 注释和空行会被忽略
alice:a-strong-password
bob:another-password
```

启用 `--users` 后会关闭自动注册，只允许文件中列出的用户名和密码登录。服务运行期间可直接保存该文件，无需重启；新增账户立即可登录，移除账户会使其现有会话失效。密码在白名单中是明文，建议执行 `chmod 600 users.txt`，并将文件放在只有服务账户能读取的位置。

常用参数：

```bash
python3 server.py --port 9000 --data /path/to/data --max-storage-gb 20
```

- `--listen`：监听地址，默认 `0.0.0.0`
- `--port`：端口，默认 `8080`
- `--data`：文件和账户数据目录，默认项目内的 `data`
- `--large-threshold-mb`：启用分块续传的大小，默认 `128`
- `--chunk-mb`：大文件分块大小，默认 `8`
- `--max-storage-gb`：每个用户的空间上限，默认 `0`（不限）
- `--users`：可选用户名密码白名单，每行 `用户名:密码`

大文件上传中断后，重新选择同一个文件即可从已校验分块继续。服务端会逐块核对 SHA-256，完成时核对分块清单并再次计算整个文件的 SHA-256。未完成上传保留 7 天。下载支持 HTTP Range。

## 后台运行

Linux 可使用 systemd，macOS 可使用 launchd；最简临时运行方式：

```bash
nohup python3 server.py > relay.log 2>&1 &
```

## 安全边界

该服务设计用于可信局域网。密码使用 PBKDF2-HMAC-SHA256 加盐保存，会话 Cookie 防脚本读取并限制为同站请求。若需要跨公网访问，请在前面配置带 HTTPS、限流和访问控制的反向代理，不要直接暴露端口。

## 测试

```bash
python3 -m unittest -v
```
