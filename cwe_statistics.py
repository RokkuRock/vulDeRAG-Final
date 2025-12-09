import requests 
from bs4 import BeautifulSoup
import json
import time
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import re

class CWECollector:
    """CWE Vulnerability Example Collector - Improved version, supports CSS class identification"""

    def __init__(self, delay=1, use_selenium=True):
        self.delay = delay
        self.use_selenium = use_selenium
        
        # Setup requests session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Setup Selenium WebDriver (Optional)
        self.driver = None
        if use_selenium:
            try:
                chrome_options = Options()
                chrome_options.add_argument('--headless')  # Headless mode
                chrome_options.add_argument('--no-sandbox')
                chrome_options.add_argument('--disable-dev-shm-usage')
                self.driver = webdriver.Chrome(options=chrome_options)
                print("[INFO] Selenium WebDriver initialized successfully")
            except Exception as e:
                print(f"[WARNING] Selenium initialization failed: {e}")
                print("[INFO] Will use requests mode")
                self.use_selenium = False

    def get_computed_style(self, element):
        """Get computed style of element using Selenium"""
        if not self.driver:
            return {}
        
        try:
            # Get background color
            bg_color = self.driver.execute_script(
                "return window.getComputedStyle(arguments[0]).backgroundColor;", 
                element
            )
            
            # Get other relevant styles
            styles = {
                'background-color': bg_color,
                'display': self.driver.execute_script(
                    "return window.getComputedStyle(arguments[0]).display;", element
                ),
                'visibility': self.driver.execute_script(
                    "return window.getComputedStyle(arguments[0]).visibility;", element
                )
            }
            return styles
        except Exception as e:
            print(f"[WARNING] Failed to get styles: {e}")
            return {}

    def rgb_to_hex(self, rgb_string):
        """Convert RGB color to Hex"""
        if not rgb_string or rgb_string == 'rgba(0, 0, 0, 0)':
            return None
            
        try:
            if rgb_string.startswith('rgb'):
                # Extract numbers
                numbers = re.findall(r'\d+', rgb_string)
                if len(numbers) >= 3:
                    r, g, b = int(numbers[0]), int(numbers[1]), int(numbers[2])
                    return f"#{r:02x}{g:02x}{b:02x}".upper()
        except Exception:
            pass
        return rgb_string

    def fetch_cwe_example_codes_selenium(self, cwe_id):
        """Fetch CWE example codes using Selenium"""
        if not self.driver:
            return self.fetch_cwe_example_codes_requests(cwe_id)
            
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        print(f"[INFO] Fetching CWE-{cwe_id} with Selenium from {url} ...")

        try:
            self.driver.get(url)
            
            # Wait for page load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            example_codes = []
            has_fixed_example = False

            # Method 1: Find all div elements with class='top'
            top_divs = self.driver.find_elements(By.CSS_SELECTOR, "div.top")
            print(f"[INFO] Found {len(top_divs)} div.top elements")
            
            for idx, div in enumerate(top_divs, start=1):
                try:
                    # Get computed styles
                    styles = self.get_computed_style(div)
                    bg_color = styles.get('background-color', '')
                    hex_color = self.rgb_to_hex(bg_color)
                    
                    # Get element text
                    text_content = div.text.strip()
                    
                    if text_content and len(text_content) > 10:
                        print(f"[DEBUG] div.top #{idx}: bg_color={bg_color}, hex={hex_color}")
                        
                        # Check if it is a fixed example (#CCCCFF)
                        is_fixed = False
                        if hex_color and hex_color.upper() == '#CCCCFF':
                            is_fixed = True
                            has_fixed_example = True
                            print(f"[SUCCESS] Found fixed example! CWE-{cwe_id}, div #{idx}")
                        
                        example_codes.append({
                            'title': f"{'Fixed ' if is_fixed else ''}Example {idx}",
                            'code': text_content,
                            'source': 'selenium_top_div',
                            'background_color': hex_color or bg_color or 'none',
                            'is_fixed': is_fixed,
                            'computed_styles': styles
                        })

                except Exception as e:
                    print(f"[WARNING] Error processing div.top #{idx}: {e}")

            # Method 2: Find all elements that might contain code
            code_selectors = [
                "div[style*='background']",
                "pre", "code", 
                "div.ExampleCode",
                "div[class*='example']",
                "div[class*='code']"
            ]
            
            for selector in code_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements:
                        styles = self.get_computed_style(element)
                        bg_color = styles.get('background-color', '')
                        hex_color = self.rgb_to_hex(bg_color)
                        text_content = element.text.strip()
                        
                        if (text_content and len(text_content) > 10 and 
                            hex_color and hex_color.upper() == '#CCCCFF'):
                            
                            # Avoid duplicates
                            if not any(ex['code'] == text_content for ex in example_codes):
                                example_codes.append({
                                    'title': f"Fixed Example ({selector})",
                                    'code': text_content,
                                    'source': f'selenium_{selector}',
                                    'background_color': hex_color,
                                    'is_fixed': True,
                                    'computed_styles': styles
                                })
                                has_fixed_example = True
                                print(f"[SUCCESS] Found fixed example via {selector}! CWE-{cwe_id}")
                                
                except Exception as e:
                    print(f"[WARNING] Error searching {selector}: {e}")

            print(f"[INFO] CWE-{cwe_id}: {len(example_codes)} examples found (Selenium), Fixed: {has_fixed_example}")
            return example_codes, has_fixed_example

        except Exception as e:
            print(f"[ERROR] Error processing CWE-{cwe_id} with Selenium: {str(e)}")
            return [], False

    def fetch_cwe_example_codes_requests(self, cwe_id):
        """Fetch CWE example codes using requests (Fallback method)"""
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        print(f"[INFO] Fetching CWE-{cwe_id} with requests from {url} ...")

        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                print(f"[ERROR] Failed to fetch CWE-{cwe_id}: status code {response.status_code}")
                return [], False

            soup = BeautifulSoup(response.text, "html.parser")
            example_codes = []
            has_fixed_example = False

            # Method 1: Search for div with class='top'
            top_divs = soup.find_all("div", class_="top")
            print(f"[INFO] Found {len(top_divs)} div.top elements")
            
            for idx, div in enumerate(top_divs, start=1):
                text_content = div.get_text().strip()
                style_attr = div.get('style', '')
                
                if text_content and len(text_content) > 10:
                    # Check background color in inline styles
                    is_fixed = False
                    if '#CCCCFF' in style_attr.upper() or '#ccccff' in style_attr:
                        is_fixed = True
                        has_fixed_example = True
                        print(f"[SUCCESS] Found inline style fixed example! CWE-{cwe_id}")
                        
                    example_codes.append({
                        'title': f"{'Fixed ' if is_fixed else ''}Example {idx}",
                        'code': text_content,
                        'source': 'requests_top_div',
                        'background_color': style_attr if style_attr else 'none',
                        'is_fixed': is_fixed
                    })

            # Method 2: Search for #CCCCFF pattern in HTML source
            html_content = response.text
            if '#CCCCFF' in html_content.upper() or '#ccccff' in html_content:
                print(f"[INFO] Found #CCCCFF in HTML source, attempting to extract...")
                
                # Find div tags containing #CCCCFF
                ccccff_pattern = r'<div[^>]*(?:style="[^"]*background[^"]*#[Cc][Cc][Cc][Ff][Ff][^"]*"|class="[^"]*top[^"]*")[^>]*>(.*?)</div>'
                matches = re.findall(ccccff_pattern, html_content, re.DOTALL | re.IGNORECASE)
                
                for idx, match in enumerate(matches):
                    clean_text = BeautifulSoup(match, "html.parser").get_text().strip()
                    if clean_text and len(clean_text) > 10:
                        example_codes.append({
                            'title': f"Fixed Example (Regex) - {idx+1}",
                            'code': clean_text,
                            'source': 'regex_ccccff',
                            'background_color': '#CCCCFF',
                            'is_fixed': True
                        })
                        has_fixed_example = True
                        print(f"[SUCCESS] Found fixed example via Regex! CWE-{cwe_id}")

            print(f"[INFO] CWE-{cwe_id}: {len(example_codes)} examples found (requests), Fixed: {has_fixed_example}")
            return example_codes, has_fixed_example

    def fetch_cwe_example_codes(self, cwe_id):
        """Unified entry point for fetching CWE example codes"""
        if self.use_selenium:
            return self.fetch_cwe_example_codes_selenium(cwe_id)
        else:
            return self.fetch_cwe_example_codes_requests(cwe_id)

    def collect_multiple_cwes(self, cwe_ids):
        """Collect example codes for multiple CWEs and count fixed codes"""
        all_examples = {}
        
        # Statistical data
        has_example_cwes = []
        no_example_cwes = []
        has_fixed_example_cwes = []
        no_fixed_example_cwes = []
        
        fixed_example_counter = 0

        for i, cwe_id in enumerate(cwe_ids, 1):
            print(f"\n[PROGRESS] Processing CWE-{cwe_id} ({i}/{len(cwe_ids)})")
            
            examples, has_fixed = self.fetch_cwe_example_codes(cwe_id)
            
            if examples:
                all_examples[cwe_id] = examples
                has_example_cwes.append(cwe_id)
                
                if has_fixed:
                    has_fixed_example_cwes.append(cwe_id)
                    fixed_example_counter += 1
                    print(f"[FIXED] CWE-{cwe_id} Has fixed example code ✅")
                else:
                    no_fixed_example_cwes.append(cwe_id)
                    print(f"[NO-FIXED] CWE-{cwe_id} No fixed example code ❌")
            else:
                no_example_cwes.append(cwe_id)
                no_fixed_example_cwes.append(cwe_id)
                print(f"[NO-EXAMPLE] CWE-{cwe_id} No example code found")

            if self.delay > 0:
                time.sleep(self.delay)

        # Create output directory
        Path("output").mkdir(exist_ok=True)

        # Save statistical results
        statistics = {
            "no_example": {
                "total": len(no_example_cwes),
                "cwe_ids": no_example_cwes,
                "description": "CWEs with no example code"
            },
            "has_example": {
                "total": len(has_example_cwes),
                "cwe_ids": has_example_cwes,
                "description": "CWEs with any example code"
            },
            "has_fixed": {
                "total": len(has_fixed_example_cwes),
                "cwe_ids": has_fixed_example_cwes,
                "description": "CWEs with fixed example code"
            },
            "no_fixed": {
                "total": len(no_fixed_example_cwes),
                "cwe_ids": no_fixed_example_cwes,
                "description": "CWEs without fixed example code"
            }
        }

        # Save various statistical files
        for key, data in statistics.items():
            filename = f"output/cwe_{key}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[INFO] Statistics files saved to output/ directory")
        return all_examples, has_example_cwes, no_example_cwes, has_fixed_example_cwes, no_fixed_example_cwes

    def save_to_json(self, cwe_examples, filename="output/cwe_examples.json"):
        """Save collected examples to JSON file"""
        output_data = {
            "collection_info": {
                "total_cwes": len(cwe_examples),
                "total_examples": sum(len(examples) for examples in cwe_examples.values()),
                "cwe_ids": list(cwe_examples.keys()),
                "method_used": "selenium" if self.use_selenium else "requests"
            },
            "cwe_examples": cwe_examples
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"[INFO] CWE examples saved to {filename}")
        return filename

    def __del__(self):
        """Cleanup Selenium WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass

def get_test_cwe_ids():
    """Return CWE IDs for testing"""
    return [79, 89, 121, 190, 416]  # CWEs known to have examples

def get_common_cwe_ids():
    """Return all CWE vulnerability type IDs"""
    return [5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 64, 65, 66, 67, 69, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 134, 135, 138, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 170, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 190, 191, 192, 193, 194, 195, 196, 197, 198, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 219, 220, 221, 222, 223, 224, 226, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 248, 250, 252, 253, 256, 257, 258, 259, 260, 261, 262, 263, 266, 267, 268, 269, 270, 271, 272, 273, 274, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 311, 312, 313, 314, 315, 316, 317, 318, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 356, 357, 358, 359, 360, 362, 363, 364, 366, 367, 368, 369, 370, 372, 374, 375, 377, 378, 379, 382, 383, 384, 385, 386, 390, 391, 392, 393, 394, 395, 396, 397, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 412, 413, 414, 415, 416, 419, 420, 421, 422, 424, 425, 426, 427, 428, 430, 431, 432, 433, 434, 435, 436, 437, 439, 440, 441, 444, 446, 447, 448, 449, 450, 451, 453, 454, 455, 456, 457, 459, 460, 462, 463, 464, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 486, 487, 488, 489, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 506, 507, 508, 509, 510, 511, 512, 514, 515, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 535, 536, 537, 538, 539, 540, 541, 543, 544, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 558, 560, 561, 562, 563, 564, 565, 566, 567, 568, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 593, 594, 595, 597, 598, 599, 600, 601, 602, 603, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 703, 704, 705, 706, 707, 708, 710, 732, 733, 749, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 804, 805, 806, 807, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 841, 842, 843, 862, 863, 908, 909, 910, 911, 912, 913, 914, 915, 916, 917, 918, 920, 921, 922, 923, 924, 925, 926, 927, 939, 940, 941, 942, 943, 1004, 1007, 1021, 1022, 1023, 1024, 1025, 1037, 1038, 1039, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1164, 1173, 1174, 1176, 1177, 1188, 1189, 1190, 1191, 1192, 1193, 1204, 1209, 1220, 1221, 1222, 1223, 1224, 1229, 1230, 1231, 1232, 1233, 1234, 1235, 1236, 1239, 1240, 1241, 1242, 1243, 1244, 1245, 1246, 1247, 1248, 1249, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 1259, 1260, 1261, 1262, 1263, 1264, 1265, 1266, 1267, 1268, 1269, 1270, 1271, 1272, 1273, 1274, 1275, 1276, 1277, 1278, 1279, 1280, 1281, 1282, 1283, 1284, 1285, 1286, 1287, 1288, 1289, 1290, 1291, 1292, 1293, 1294, 1295, 1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303, 1304, 1310, 1311, 1312, 1313, 1314, 1315, 1316, 1317, 1318, 1319, 1320, 1321, 1322, 1323, 1325, 1326, 1327, 1328, 1329, 1330, 1331, 1332, 1333, 1334, 1335, 1336, 1338, 1339, 1341, 1342, 1351, 1357, 1384, 1385, 1386, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1419, 1420, 1421, 1422, 1423, 1426, 1427, 1428, 1429, 1431]

def main():
    """Main function - Collect CWE examples and count fixed codes"""
    print("=== CWE Fixed Example Statistician (Improved Version) ===")
    print("Supports Selenium to get computed CSS styles")

    # Select processing mode
    print("\nSelect processing mode:")
    print("1. Use Selenium (Recommended, can get computed CSS styles)")
    print("2. Use requests (Fast, but can only check inline styles)")
    
    mode_choice = input("Please select mode (1-2): ").strip()
    use_selenium = mode_choice == "1"

    # Select CWE range
    print("\nSelect collection range:")
    print("1. Test mode (5 known CWEs)")
    print("2. Full statistics (943 CWEs)")
    print("3. Custom CWE IDs")

    range_choice = input("Please select range (1-3): ").strip()

    if range_choice == "1":
        cwe_ids = get_test_cwe_ids()
        print(f"Test mode: Counting {len(cwe_ids)} CWEs")
    elif range_choice == "2":
        cwe_ids = get_common_cwe_ids()
        print(f"Full mode: Counting {len(cwe_ids)} CWEs")
    else:  # range_choice == "3"
        cwe_input = input("Please enter CWE IDs (comma separated, e.g., 121,416,79): ").strip()
        try:
            cwe_ids = [int(x.strip()) for x in cwe_input.split(',')]
        except ValueError:
            print("[ERROR] Invalid CWE ID format")
            return

    # Initialize collector
    collector = CWECollector(delay=2, use_selenium=use_selenium)

    print(f"\nStarting to count fixed examples for {len(cwe_ids)} CWEs...")
    print("=" * 60)

    try:
        # Collect examples and count
        cwe_examples, has_example, no_example, has_fixed, no_fixed = collector.collect_multiple_cwes(cwe_ids)

        # Save complete example data
        if cwe_examples:
            collector.save_to_json(cwe_examples)

        # Display statistical results
        total_cwes = len(cwe_ids)
        total_with_examples = len(has_example)
        total_without_examples = len(no_example)
        total_with_fixed = len(has_fixed)
        total_without_fixed = len(no_fixed)

        print(f"\n" + "=" * 60)
        print("🎯 CWE Fixed Example Statistics Results (Improved Version)")
        print("=" * 60)
        print(f"🔧 Processing Mode: {'Selenium' if use_selenium else 'Requests'}")
        print(f"📊 Total CWEs Counted: {total_cwes}")
        print(f"")
        print(f"📝 CWEs with any Example Code:")
        print(f"   ✅ Count: {total_with_examples}")
        print(f"   📈 Ratio: {(total_with_examples/total_cwes)*100:.1f}%")
        print(f"")
        print(f"🛠️ CWEs with Fixed Example Code:")
        print(f"   ✅ Count: {total_with_fixed}")
        print(f"   📈 Ratio: {(total_with_fixed/total_cwes)*100:.1f}%")
        print(f"   🎯 CWE IDs: {has_fixed}")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\n[INFO] User interrupted program execution")
    except Exception as e:
        print(f"\n[ERROR] Program execution error: {e}")
    finally:
        # Ensure resource cleanup
        if hasattr(collector, 'driver') and collector.driver:
            collector.driver.quit()

if __name__ == "__main__":
    main()