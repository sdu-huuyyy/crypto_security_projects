import cv2
import numpy as np
import pywt
from skimage.metrics import peak_signal_noise_ratio as psnr

EMBED_STRENGTH = 20  #水印嵌入的强度参数
WATERMARK_W = 32  #水印图像的宽度
WATERMARK_H = 32  #水印图像的高度
RANDOM_SEED = 42  #伪随机数发生器的种子


class DwtDctEmbedder:
    """
    基于DWT和DCT的图像水印处理器。
    该类负责水印的嵌入与提取。
    """

    def __init__(self, strength=EMBED_STRENGTH):
        self.strength = strength

    def _preprocess_watermark(self, wm_img):
        """
        将水印图像调整尺寸并转换为二进制位序列
        """
        resized_wm = cv2.resize(wm_img, (WATERMARK_W, WATERMARK_H))
        return (resized_wm > 127).astype(np.uint8).flatten()

    def insert_watermark(self, carrier_img, wm_img):
        """
        将水印嵌入到载体图像中
        """
        #准备水印：将水印图像转换为一维的二进制位序列
        wm_bits = self._preprocess_watermark(wm_img)

        #图像分解：对载体图像进行DWT分解
        dwt_coefficients = pywt.dwt2(carrier_img, 'haar')
        low_pass_ll, (high_pass_lh, high_pass_hl, high_pass_hh) = dwt_coefficients

        #定义嵌入区域：选择LH和HL子带
        lh_height, lh_width = high_pass_lh.shape
        hl_height, hl_width = high_pass_hl.shape
        embedding_h = min(lh_height, hl_height)
        embedding_w = min(lh_width, hl_width)

        #确保嵌入区域尺寸可用
        embedding_h -= embedding_h % WATERMARK_H
        embedding_w -= embedding_w % WATERMARK_W

        #嵌入过程：通过伪随机位置在 DCT 域修改系数
        np.random.seed(RANDOM_SEED)

        for idx, bit_value in enumerate(wm_bits):
            #获取随机嵌入坐标
            rand_h_lh = np.random.randint(0, embedding_h - 1)
            rand_w_lh = np.random.randint(0, embedding_w - 1)
            rand_h_hl = np.random.randint(0, embedding_h - 1)
            rand_w_hl = np.random.randint(0, embedding_w - 1)

            #对2x2块进行DCT变换
            dct_block_lh = cv2.dct(np.float32(high_pass_lh[rand_h_lh:rand_h_lh + 2, rand_w_lh:rand_w_lh + 2]))
            dct_block_hl = cv2.dct(np.float32(high_pass_hl[rand_h_hl:rand_h_hl + 2, rand_w_hl:rand_w_hl + 2]))

            #根据水印位修改DCT系数
            if bit_value == 1:
                dct_block_lh[0, 1] += self.strength
                dct_block_hl[1, 0] += self.strength
            else:
                dct_block_lh[0, 1] -= self.strength
                dct_block_hl[1, 0] -= self.strength

            #IDCT反变换回子带
            high_pass_lh[rand_h_lh:rand_h_lh + 2, rand_w_lh:rand_w_lh + 2] = cv2.idct(dct_block_lh)
            high_pass_hl[rand_h_hl:rand_h_hl + 2, rand_w_hl:rand_w_hl + 2] = cv2.idct(dct_block_hl)

        #图像重构：使用修改后的子带系数进行IDWT
        final_image = pywt.idwt2((low_pass_ll, (high_pass_lh, high_pass_hl, high_pass_hh)), 'haar')
        return np.clip(final_image, 0, 255).astype(np.uint8)

    def retrieve_watermark(self, watermarked_img):
        """
        从带水印的图像中提取水印
        """
        #图像分解：对带水印图像进行DWT
        dwt_coefficients = pywt.dwt2(watermarked_img, 'haar')
        low_pass_ll, (high_pass_lh, high_pass_hl, high_pass_hh) = dwt_coefficients

        #确定提取区域
        lh_height, lh_width = high_pass_lh.shape
        hl_height, hl_width = high_pass_hl.shape
        embedding_h = min(lh_height, hl_height)
        embedding_w = min(lh_width, hl_width)

        embedding_h -= embedding_h % WATERMARK_H
        embedding_w -= embedding_w % WATERMARK_W

        extracted_bits = np.zeros(WATERMARK_W * WATERMARK_H, dtype=np.float32)

        # 3. 提取过程：使用与嵌入时相同的随机种子
        np.random.seed(RANDOM_SEED)

        for i in range(WATERMARK_W * WATERMARK_H):
            #获取与嵌入时相同的随机坐标
            rand_h_lh = np.random.randint(0, embedding_h - 1)
            rand_w_lh = np.random.randint(0, embedding_w - 1)
            rand_h_hl = np.random.randint(0, embedding_h - 1)
            rand_w_hl = np.random.randint(0, embedding_w - 1)

            #提取DCT域系数
            dct_block_lh = cv2.dct(np.float32(high_pass_lh[rand_h_lh:rand_h_lh + 2, rand_w_lh:rand_w_lh + 2]))
            dct_block_hl = cv2.dct(np.float32(high_pass_hl[rand_h_hl:rand_h_hl + 2, rand_w_hl:rand_w_hl + 2]))

            #根据DCT系数差值判断水印位
            value_diff = (dct_block_lh[0, 1] + dct_block_hl[1, 0]) / 2.0
            extracted_bits[i] = 1 if value_diff > 0 else 0

        #重塑为二维水印图像
        retrieved_wm = extracted_bits.reshape(WATERMARK_H, WATERMARK_W)
        return retrieved_wm.astype(np.uint8) * 255


def main_execution_flow():
    """
    负责整个水印处理流水线的执行。
    """
    #实例化水印处理器
    embedder_instance = DwtDctEmbedder(strength=EMBED_STRENGTH)

    #从文件加载图像
    original_carrier = cv2.imread("host.jpg", cv2.IMREAD_COLOR)
    watermark_source = cv2.imread("watermark.jpg", cv2.IMREAD_GRAYSCALE)

    if original_carrier is None or watermark_source is None:
        print("错误：无法加载图像文件，请检查路径。")
        return

    #准备真值水印
    resized_true_wm = cv2.resize(watermark_source, (WATERMARK_W, WATERMARK_H))
    binary_true_wm = (resized_true_wm > 127).astype(np.uint8)

    print("--- 水印处理流程开始 ---")

    #分离通道，选择蓝色通道进行处理
    b_channel, g_channel, r_channel = cv2.split(original_carrier)

    #执行水印嵌入
    watermarked_blue_channel = embedder_instance.insert_watermark(b_channel, watermark_source)
    final_watermarked_image = cv2.merge((watermarked_blue_channel, g_channel, r_channel))
    cv2.imwrite("watermarked_output.png", final_watermarked_image)

    print("水印嵌入完成。开始评估鲁棒性...")

    #定义并执行各种攻击测试
    test_attacks = {
        "水平翻转": lambda img: cv2.flip(img, 1),
        "图像平移": lambda img: cv2.warpAffine(img, np.float32([[1, 0, 10], [0, 1, 10]]), (img.shape[1], img.shape[0])),
        "中心裁剪": lambda img: cv2.resize(
            img[int(img.shape[0] * 0.1):int(img.shape[0] * 0.9), int(img.shape[1] * 0.1):int(img.shape[1] * 0.9)],
            (img.shape[1], img.shape[0])),
        "对比度调整": lambda img: cv2.convertScaleAbs(img, alpha=1.5, beta=10),
        "高斯噪声": lambda img: np.clip(img.astype(np.float32) + np.random.normal(0, 15, img.shape).astype(np.float32),
                                        0,
                                        255).astype(np.uint8)
    }

    for attack_name, attack_fn in test_attacks.items():
        print(f"--> 运行测试用例: [{attack_name}]")

        # 对带水印图像应用攻击
        attacked_img = attack_fn(final_watermarked_image)
        cv2.imwrite(f"attacked_with_{attack_name}.png", attacked_img)

        # 提取攻击后的水印
        attacked_b_channel = cv2.split(attacked_img)[0]
        retrieved_wm_raw = embedder_instance.retrieve_watermark(attacked_b_channel)

        # 评估提取结果
        retrieved_wm_binary = (retrieved_wm_raw > 127).astype(np.uint8)

        accuracy, ber_rate = evaluate_performance(binary_true_wm, retrieved_wm_binary)

        pass_status = "通过" if accuracy > 50 else "未通过"
        print(f"结果：准确率={accuracy:.2f}%, 误码率（BER）={ber_rate:.2f}% -> 测试{pass_status}\n")

        cv2.imwrite(f"extracted_from_{attack_name}_wm.png", retrieved_wm_raw)


def evaluate_performance(true_wm_data, extracted_wm_data):
    """
    计算并返回水印的准确率和误码率（BER）。
    """
    if true_wm_data.shape != extracted_wm_data.shape:
        extracted_wm_data = cv2.resize(extracted_wm_data, (true_wm_data.shape[1], true_wm_data.shape[0]))

    total_elements = true_wm_data.size
    correct_matches = np.sum(true_wm_data == extracted_wm_data)

    accuracy = (correct_matches / total_elements) * 100
    ber_rate = (1 - (correct_matches / total_elements)) * 100

    return accuracy, ber_rate


if __name__ == "__main__":
    main_execution_flow()
