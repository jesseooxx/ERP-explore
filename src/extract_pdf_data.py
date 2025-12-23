"""
從原始 PDF 提取數據用於測試
"""

import PyPDF2
import re

def extract_data_from_pdf(pdf_path):
    """從 PDF 提取結構化數據"""

    with open(pdf_path, 'rb') as f:
        pdf = PyPDF2.PdfReader(f)
        page1_text = pdf.pages[0].extract_text()

    print("第一頁文本:")
    print("="*60)
    print(page1_text[:1000])
    print("="*60)

    # 嘗試提取關鍵字段
    data = {}

    # Date
    date_match = re.search(r'Date\s*:\s*([^\n]+)', page1_text)
    if date_match:
        data[1] = date_match.group(1).strip()

    # ORDER
    order_match = re.search(r'ORDER:\s*([^\n]+)', page1_text)
    if date_match:
        data[2] = order_match.group(1).strip() if order_match else ""

    # Ref
    ref_match = re.search(r'Ref\.\s*:\s*([^\n]+)', page1_text)
    if ref_match:
        data[3] = ref_match.group(1).strip()

    # Cust#
    cust_match = re.search(r'Cust#:\s*([^\n]+)', page1_text)
    if cust_match:
        data[4] = cust_match.group(1).strip()

    # Tel
    tel_match = re.search(r'Tel\s*#:\s*([^\n]+)', page1_text)
    if tel_match:
        data[5] = tel_match.group(1).strip()

    # Fax
    fax_match = re.search(r'Fax\s*#:\s*([^\n]+)', page1_text)
    if fax_match:
        data[6] = fax_match.group(1).strip()

    # Messrs
    messrs_match = re.search(r'Messrs\.\s*:\s*([^\n]+)', page1_text)
    if messrs_match:
        data['messrs'] = messrs_match.group(1).strip()

    print("\n提取的數據:")
    print("="*60)
    for k, v in data.items():
        print(f"  {k}: {v}")

    return data

if __name__ == "__main__":
    data = extract_data_from_pdf('nrp_backup/sample_PI.pdf')

    # 生成Python字典代碼
    print("\n\nPython 代碼:")
    print("="*60)
    print("test_data = {")
    for k, v in data.items():
        if isinstance(k, int):
            print(f"    {k}: \"{v}\",")
    print("}")
