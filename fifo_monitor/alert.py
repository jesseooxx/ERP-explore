"""警告視窗模組"""
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any


class FIFOAlertWindow:
    """FIFO 違規警告視窗"""

    def __init__(
        self,
        current_pi: str,
        current_date: str,
        product: str,
        earlier_orders: List[Dict[str, Any]]
    ):
        self.current_pi = current_pi
        self.current_date = current_date
        self.product = product
        self.earlier_orders = earlier_orders

        self.root = tk.Tk()
        self.root.title("⚠️ FIFO 訂單警告")
        self.root.geometry("680x420")
        self.root.resizable(False, False)

        # 置中顯示
        self.root.eval('tk::PlaceWindow . center')

        self._create_widgets()

    def _create_widgets(self):
        """建立視窗元件"""
        # 標題
        title_frame = tk.Frame(self.root, bg="#FFF3CD", padx=10, pady=10)
        title_frame.pack(fill=tk.X)

        tk.Label(
            title_frame,
            text="⚠️ FIFO 訂單警告",
            font=("Microsoft JhengHei", 14, "bold"),
            bg="#FFF3CD",
            fg="#856404"
        ).pack()

        # 當前訂單資訊
        current_frame = tk.LabelFrame(
            self.root,
            text="您正在處理的訂單",
            font=("Microsoft JhengHei", 10),
            padx=10, pady=5
        )
        current_frame.pack(fill=tk.X, padx=10, pady=10)

        # 格式化日期顯示
        formatted_date = f"{self.current_date[:4]}/{self.current_date[4:6]}/{self.current_date[6:]}"

        tk.Label(
            current_frame,
            text=f"PI: {self.current_pi}    日期: {formatted_date}    產品: {self.product}",
            font=("Consolas", 11)
        ).pack()

        # 警告訊息
        tk.Label(
            self.root,
            text="⚠️ 以下訂單還有剩餘數量，依 FIFO 應優先處理：",
            font=("Microsoft JhengHei", 10),
            fg="#DC3545"
        ).pack(pady=(10, 5))

        # 訂單清單（使用 Treeview）
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("pi_no", "order_date", "remaining", "elapsed")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=8)

        self.tree.heading("pi_no", text="PI 編號")
        self.tree.heading("order_date", text="訂單日期")
        self.tree.heading("remaining", text="剩餘數量")
        self.tree.heading("elapsed", text="已過時間")

        self.tree.column("pi_no", width=160, minwidth=140, anchor=tk.CENTER)
        self.tree.column("order_date", width=120, minwidth=100, anchor=tk.CENTER)
        self.tree.column("remaining", width=120, minwidth=100, anchor=tk.CENTER)
        self.tree.column("elapsed", width=120, minwidth=100, anchor=tk.CENTER)

        # 插入資料
        for order in self.earlier_orders:
            formatted_date = f"{order['order_date'][:4]}/{order['order_date'][4:6]}/{order['order_date'][6:]}"
            self.tree.insert("", tk.END, values=(
                order['pi_no'],
                formatted_date,
                f"{order['remaining']:,.0f}",
                order['elapsed']
            ))

        # 捲軸
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 按鈕區
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=15)

        tk.Button(
            btn_frame,
            text="我知道了",
            command=self.root.destroy,
            width=12,
            font=("Microsoft JhengHei", 10)
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            btn_frame,
            text="複製清單",
            command=self._copy_to_clipboard,
            width=12,
            font=("Microsoft JhengHei", 10)
        ).pack(side=tk.LEFT, padx=10)

    def _copy_to_clipboard(self):
        """複製清單到剪貼簿"""
        lines = [f"FIFO 警告 - PI: {self.current_pi}, 產品: {self.product}", ""]
        lines.append("應優先處理的訂單：")
        lines.append("-" * 50)

        for order in self.earlier_orders:
            formatted_date = f"{order['order_date'][:4]}/{order['order_date'][4:6]}/{order['order_date'][6:]}"
            lines.append(
                f"PI: {order['pi_no']:<12} "
                f"日期: {formatted_date}  "
                f"剩餘: {order['remaining']:>8,.0f}  "
                f"已過: {order['elapsed']}"
            )

        text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

        # 顯示複製成功提示
        self.root.title("✓ 已複製到剪貼簿")
        self.root.after(2000, lambda: self.root.title("⚠️ FIFO 訂單警告"))

    def show(self):
        """顯示視窗"""
        # 置頂顯示
        self.root.attributes('-topmost', True)
        self.root.mainloop()


def show_alert(violation) -> None:
    """
    顯示 FIFO 違規警告。

    Args:
        violation: FIFOViolation 物件
    """
    window = FIFOAlertWindow(
        current_pi=violation.current_pi,
        current_date=violation.current_date,
        product=violation.product,
        earlier_orders=violation.earlier_orders
    )
    window.show()
