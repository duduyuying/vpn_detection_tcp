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

