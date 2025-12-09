import requests
from bs4 import BeautifulSoup
import json
import time
from pathlib import Path
from langchain_core.documents import Document

class CWECollector:
    """CWE漏洞範例收集器"""

    def __init__(self, delay=1):
        self.delay = delay  # 請求間隔，避免過於頻繁的請求
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def fetch_cwe_example_codes(self, cwe_id):
        """抓取指定CWE ID的範例程式碼"""
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        print(f"[INFO] Fetching CWE-{cwe_id} from {url} ...")

        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                print(f"[ERROR] Failed to fetch CWE-{cwe_id}: status code {response.status_code}")
                return []

            soup = BeautifulSoup(response.text, "html.parser")

            # 尋找範例程式碼區塊
            example_codes = []

            # 方法1: 尋找 id="ExampleCode" 的 div
            example_divs = soup.find_all("div", id="ExampleCode")
            for idx, div in enumerate(example_divs, start=1):
                code_container = div.find("div", class_="top")
                if code_container:
                    code_html = code_container.decode_contents().replace("<br/>", "\n")
                    code_soup = BeautifulSoup(code_html, "html.parser")
                    code_text = code_soup.get_text().strip()
                    if code_text:
                        example_codes.append({
                            'title': f"Example {idx}",
                            'code': code_text,
                            'source': 'ExampleCode'
                        })

            # 方法2: 尋找 <pre> 標籤中的程式碼
            pre_tags = soup.find_all("pre")
            for idx, pre in enumerate(pre_tags, start=len(example_codes)+1):
                code_text = pre.get_text().strip()
                if code_text and len(code_text) > 20:  # 過濾太短的內容
                    example_codes.append({
                        'title': f"Code Block {idx}",
                        'code': code_text,
                        'source': 'pre'
                    })

            # 方法3: 尋找包含程式語言關鍵字的程式碼區塊
            code_blocks = soup.find_all("div", class_="code")
            for idx, block in enumerate(code_blocks, start=len(example_codes)+1):
                code_text = block.get_text().strip()
                if code_text:
                    example_codes.append({
                        'title': f"Vulnerable Code {idx}",
                        'code': code_text,
                        'source': 'code_class'
                    })

            print(f"[SUCCESS] Found {len(example_codes)} examples for CWE-{cwe_id}")
            return example_codes

        except Exception as e:
            print(f"[ERROR] Exception while fetching CWE-{cwe_id}: {str(e)}")
            return []

    def collect_multiple_cwes(self, cwe_ids):
        """收集多個CWE的範例程式碼"""
        all_examples = {}

        for cwe_id in cwe_ids:
            examples = self.fetch_cwe_example_codes(cwe_id)
            if examples:
                all_examples[cwe_id] = examples
                print(f"[INFO] CWE-{cwe_id}: {len(examples)} examples collected")
            else:
                print(f"[WARN] No examples found for CWE-{cwe_id}")

            # 添加延遲避免過於頻繁的請求
            if self.delay > 0:
                time.sleep(self.delay)

        return all_examples

    def examples_to_documents(self, cwe_examples):
        """將CWE範例轉換為LangChain Documents格式"""
        documents = []

        for cwe_id, examples in cwe_examples.items():
            for i, example in enumerate(examples):
                metadata = {
                    "cwe_id": f"CWE-{cwe_id}",
                    "example_title": example['title'],
                    "source": example['source'],
                    "file": f"cwe_{cwe_id}_example_{i+1}",
                    "bug_block_id": f"{cwe_id}_{i+1}",
                    "vulnerability_type": f"CWE-{cwe_id}"
                }

                # 為程式碼添加上下文資訊
                content = f"# CWE-{cwe_id} - {example['title']}\n{example['code']}"

                documents.append(Document(
                    page_content=content,
                    metadata=metadata
                ))

        return documents

    def save_to_json(self, cwe_examples, filename="cwe_examples.json"):
        """將收集的範例保存為JSON檔案"""
        output_data = {
            "collection_info": {
                "total_cwes": len(cwe_examples),
                "total_examples": sum(len(examples) for examples in cwe_examples.values()),
                "cwe_ids": list(cwe_examples.keys())
            },
            "cwe_examples": cwe_examples
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"[INFO] CWE examples saved to {filename}")
        return filename

def get_common_cwe_ids():
    """返回所有共943個CWE漏洞類型ID (已更新為完整列表)"""
    return [5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 64, 65, 66, 67, 69, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 134, 135, 138, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 170, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 190, 191, 192, 193, 194, 195, 196, 197, 198, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 219, 220, 221, 222, 223, 224, 226, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 248, 250, 252, 253, 256, 257, 258, 259, 260, 261, 262, 263, 266, 267, 268, 269, 270, 271, 272, 273, 274, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 311, 312, 313, 314, 315, 316, 317, 318, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 356, 357, 358, 359, 360, 362, 363, 364, 366, 367, 368, 369, 370, 372, 374, 375, 377, 378, 379, 382, 383, 384, 385, 386, 390, 391, 392, 393, 394, 395, 396, 397, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 412, 413, 414, 415, 416, 419, 420, 421, 422, 424, 425, 426, 427, 428, 430, 431, 432, 433, 434, 435, 436, 437, 439, 440, 441, 444, 446, 447, 448, 449, 450, 451, 453, 454, 455, 456, 457, 459, 460, 462, 463, 464, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 486, 487, 488, 489, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 506, 507, 508, 509, 510, 511, 512, 514, 515, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 535, 536, 537, 538, 539, 540, 541, 543, 544, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 558, 560, 561, 562, 563, 564, 565, 566, 567, 568, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 593, 594, 595, 597, 598, 599, 600, 601, 602, 603, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 703, 704, 705, 706, 707, 708, 710, 732, 733, 749, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 804, 805, 806, 807, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 841, 842, 843, 862, 863, 908, 909, 910, 911, 912, 913, 914, 915, 916, 917, 918, 920, 921, 922, 923, 924, 925, 926, 927, 939, 940, 941, 942, 943, 1004, 1007, 1021, 1022, 1023, 1024, 1025, 1037, 1038, 1039, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1164, 1173, 1174, 1176, 1177, 1188, 1189, 1190, 1191, 1192, 1193, 1204, 1209, 1220, 1221, 1222, 1223, 1224, 1229, 1230, 1231, 1232, 1233, 1234, 1235, 1236, 1239, 1240, 1241, 1242, 1243, 1244, 1245, 1246, 1247, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 1259, 1260, 1261, 1262, 1263, 1264, 1265, 1266, 1267, 1268, 1269, 1270, 1271, 1272, 1273, 1274, 1275, 1276, 1277, 1278, 1279, 1280, 1281, 1282, 1283, 1284, 1285, 1286, 1287, 1288, 1289, 1290, 1291, 1292, 1293, 1294, 1295, 1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303, 1304, 1310, 1311, 1312, 1313, 1314, 1315, 1316, 1317, 1318, 1319, 1320, 1321, 1322, 1323, 1325, 1326, 1327, 1328, 1329, 1330, 1331, 1332, 1333, 1334, 1335, 1336, 1338, 1339, 1341, 1342, 1351, 1357, 1384, 1385, 1386, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1419, 1420, 1421, 1422, 1423, 1426, 1427, 1428, 1429, 1431]

def main():
    """主函數 - 收集CWE範例"""
    print("=== CWE 漏洞範例收集器 ===")

    # 初始化收集器
    collector = CWECollector(delay=1)

    # 可以選擇收集哪些CWE
    print("選擇收集模式:")
    print("1. 常見漏洞類型 (推薦)")
    print("2. 自定義CWE ID")
    print("3. 小範圍測試")

    choice = input("請選擇 (1-3): ").strip()

    if choice == "1":
        cwe_ids = get_common_cwe_ids()
        print(f"將收集 {len(cwe_ids)} 種常見漏洞類型的範例")
    elif choice == "2":
        cwe_input = input("請輸入CWE ID (用逗號分隔，如: 121,416,79): ").strip()
        try:
            cwe_ids = [int(x.strip()) for x in cwe_input.split(',')]
        except ValueError:
            print("[ERROR] 無效的CWE ID格式")
            return
    else:  # choice == "3" or default
        cwe_ids = [121, 416, 79]  # 小範圍測試
        print("測試模式: 收集 CWE-121, CWE-416, CWE-79")

    print(f"\n開始收集 {len(cwe_ids)} 個CWE的範例程式碼...")
    print("=" * 50)

    # 收集範例
    cwe_examples = collector.collect_multiple_cwes(cwe_ids)

    if not cwe_examples:
        print("[ERROR] 沒有收集到任何範例")
        return

    # 統計資訊
    total_examples = sum(len(examples) for examples in cwe_examples.values())
    print(f"\n收集完成!")
    print(f"成功收集 {len(cwe_examples)} 種CWE類型")
    print(f"總共 {total_examples} 個程式碼範例")

    # 保存為JSON
    json_file = collector.save_to_json(cwe_examples)

    # 顯示收集結果摘要
    print(f"\n=== 收集結果摘要 ===")
    for cwe_id, examples in cwe_examples.items():
        print(f"CWE-{cwe_id}: {len(examples)} 個範例")
        if examples:
            print(f"  範例預覽: {examples[0]['title']} - {examples[0]['code'][:300]}...")

    print(f"\n範例已保存至: {json_file}")
    print("可以使用這些資料建構RAG向量資料庫")

if __name__ == "__main__":
    main()
