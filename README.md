# VPN Detection via Inner TCP Patterns

基于内层 TCP 握手与数据–ACK 时序模式的 VPN 流量检测代码及预处理数据集。检测器采用规则判定，无需训练模型，也无需解密流量载荷。

## 文件说明

| 文件 | 用途 |
| --- | --- |
| `vpn_detector_v4.py` | 双分支 VPN 检测器与批量评估入口 |
| `handshake_processed.tar.gz` | 预处理后的流级 JSON 数据集，通过 Git LFS 存储，594,800,227 字节（约 567.25 MiB） |

## 环境与下载

需要 Python 3.8 或更新版本，仅使用 Python 标准库，无需安装第三方 Python 包。下载数据集需要安装 [Git LFS](https://git-lfs.com/)。

```bash
git lfs install
git clone https://github.com/duduyuying/vpn_detection_tcp.git
cd vpn_detection_tcp
git lfs pull
python -c "from pathlib import Path; Path('handshake_processed').mkdir(exist_ok=True)"
tar -xzf handshake_processed.tar.gz -C handshake_processed
python -c "from pathlib import Path; p=Path('handshake_processed/handshake_VPN_processed'); [(p/(s+'_lightway')).rename(p/(s+'_lightaway')) for s in ('ssh','scp') if (p/(s+'_lightway')).exists() and not (p/(s+'_lightaway')).exists()]"
```

若已克隆仓库，在仓库目录执行 `git lfs pull` 即可获取数据文件。GitHub 页面上的源码 ZIP 不一定包含 LFS 实体文件，建议使用上述命令下载。

压缩包内直接包含 `handshake_VPN_processed/` 和 `handshake_nonVPN_processed/`，因此需要通过 `-C handshake_processed` 指定解压目录。原始包中的 `ssh_lightway`、`scp_lightway` 与脚本期望的 `ssh_lightaway`、`scp_lightaway` 拼写不同；最后一条命令对解压后的目录重命名，使代码无需修改即可读取这两类流量。

数据包 SHA-256：

```text
46de7fe6cc4e731790c2987097fba3ca8ba068aef26e35cac94eafe73c57d512
```

解压后保持以下相对路径，检测器会自动从脚本所在目录查找数据：

```text
vpn_detection_tcp/
├── README.md
├── vpn_detector_v4.py
├── handshake_processed.tar.gz
└── handshake_processed/
    ├── handshake_VPN_processed/
    │   ├── web_openvpnTCP/
    │   ├── web_openvpnUDP/
    │   ├── web_wireguard/
    │   └── ...
    └── handshake_nonVPN_processed/
        ├── web_nonVPN/
        ├── ssh_nonVPN/
        ├── scp_nonVPN/
        └── CIC_monday/
```

## 检测方法

检测器首先保留携带数据的包，再按方向变化或相邻包间隔大于 10 ms 划分 burst。

- **Track B：握手与因果 ACK 验证。** 在前 `k_max` 个 burst 中寻找符合内层 TCP 三次握手的方向、大小和时间模式，再检查后续数据与反向 ACK 的配对关系。
- **Track A：ACK 一致性检测。** 寻找重复出现的数据–反向小包配对，补充未找到握手时的检测。此分支在协议字段为 `udp` 或未提供协议时运行；显式标记为其他协议的流不进入此分支。

输出标签 `1` 表示 VPN，`0` 表示非 VPN。规则仅使用可见的包大小、方向和时间信息；名称中的“内层 TCP”表示对其通信模式的推断，并非直接解析加密载荷中的 TCP 头。

## 数据划分

每个子目录内的 JSON 文件按文件名排序；以下划分完全由代码中的目录列表和切片决定，没有随机划分。

| 参数 `--dataset` | VPN 正样本 | 非 VPN 负样本 |
| --- | --- | --- |
| `calibration` | 已知协议各子目录的前 1,000 条流 | `web_nonVPN`、`ssh_nonVPN`、`scp_nonVPN` 中的全部流 |
| `standard` | 已知协议各子目录第 1,001 条及之后的流 | `CIC_monday` 中的全部流 |
| `openworld` | 未知协议各子目录的全部流 | 无 |

已知协议为 OpenVPN TCP、OpenVPN UDP、WireGuard，对应目录后缀 `openvpnTCP`、`openvpnUDP`、`wireguard`；未知协议对应后缀 `ikev2`、`lightaway`、`nordlynx`。每类协议分别包含 `web`、`ssh`、`scp` 三种业务。`lightaway` 按数据与代码中的实际拼写保留。

`openworld` 仅包含正样本，适合观察未知 VPN 的检出率。由于没有负样本，脚本在此模式输出的 FPR 为分母为零时的默认值 `0`，不代表实测误报率。

## 运行

在仓库目录执行：

```bash
python vpn_detector_v4.py --dataset calibration --k_max 9 --round 0
python vpn_detector_v4.py --dataset standard --k_max 9 --round 0
python vpn_detector_v4.py --dataset openworld --k_max 9 --round 0
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--dataset` | `calibration` | 选择评估数据划分 |
| `--k_max` | `9` | 握手候选扫描的 burst 窗口大小 |
| `--round` | `0` | 结果文件编号，不控制随机种子或数据重划分 |

结果打印到终端，并写入：

```text
results/v4_kmax9_calibration_r0_results.md
results/v4_kmax9_standard_r0_results.md
results/v4_kmax9_openworld_r0_results.md
```

报告包含 TP、FP、TN、FN、TPR、FPR、Precision、F1、分目录统计、处理速度及部分误报文件路径。相同参数与编号再次运行会覆盖同名报告。

## 输入 JSON 格式

每个 JSON 对应一条流。下面展示检测器使用的字段：

```json
{
  "flow": {"protocol": "udp"},
  "packets": [
    {"ts": 0.0, "size": 100, "direction": 0, "is_data_carrying": true},
    {"ts": 0.03, "size": 100, "direction": 1, "is_data_carrying": true}
  ]
}
```

`ts` 为以秒计的时间戳，`size` 为输入数据中记录的包大小，`direction` 为方向编码（0/1），`is_data_carrying` 表示是否携带数据。包应按时间顺序排列；示例仅说明字段格式，实际数据少于 6 个携带数据的包时会直接判为非 VPN。

处理 JSON 或分类出现异常时，当前脚本会记录处理错误并将该流预测为非 VPN；评估时应检查报告中的 `Processing errors`，避免把处理失败误认为有效检测结果。若提示目录不存在或 `No flows found`，请检查数据集是否完整下载、解压以及目录层级是否正确。

本仓库提供代码与预处理输入；具体指标应以对应数据划分上的实际运行报告为准。
