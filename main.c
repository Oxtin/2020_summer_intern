/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2020 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under Ultimate Liberty license
  * SLA0044, the "License"; You may not use this file except in compliance with
  * the License. You may obtain a copy of the License at:
  *                             www.st.com/SLA0044
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usb_device.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "usbd_customhid.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
#ifdef __GNUC__
  #define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#else
  #define PUTCHAR_PROTOTYPE int fputc(int ch, FILE *f)
#endif /* __GNUC__ */
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
I2C_HandleTypeDef hi2c1;

I2S_HandleTypeDef hi2s3;

RNG_HandleTypeDef hrng;

SPI_HandleTypeDef hspi1;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
RNG_HandleTypeDef hrng;
USBD_HandleTypeDef hUsbDeviceFS;

extern u8 totalOutDataPacket;
extern u8 nowOutDataPacket;

extern u8 receivedBuf[1024];
u8 receivedData[1024];

const u8 broadcastCID[4] = {0xff, 0xff, 0xff, 0xff};
u8 myCID[4] = {0x8, 0x7, 0x8, 0x7};

u16 payloadOffset;
u8 payloadData[1024];
u8 sendBuf[1024];

u8 aaguid[16] = {0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87};

// for ECDH
nn scalar_a;
nn_t a = &scalar_a;
u8 aG_x[32], aG_y[32];
u8 bG_x[32], bG_y[32];
u8 abG_x[32], abG_y[32];
u8 sharedSecret[32];

// for AES-CBC
u8 initialVector[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

// for PIN
u8 isSetPIN;
const u8 retriesMax = 8;
u8 pinRetries;
u8 consecutivePinErr = 0; // 3 times
u8 pinHash[16] = {0x59, 0x94, 0x47, 0x1a, 0xbb, 0x01, 0x11, 0x2a, 0xfc, 0xc1, 0x81, 0x59, 0xf6, 0xcc, 0x74, 0xb4};
u8 pinTokenLen;
u8 pinToken[32];

// for makeCredential and getAssertion
u8 clientDataHash[32];

u8 rpIDLen; // only deal with len < 2^8
u8 rpID[255];

u8 userIDLen;
u8 userID[255];

u8 my_priv_key_len;
u8 my_priv_key[32 + 5];
u8 my_pub_key[64 + 5];

u8 my_sig_r[32 + 1];
u8 my_sig_s[32 + 1];

u8 encodedSig[75];
u8 encodedSigLen;

// for getAssertion
uint32_t signCount = 0;
u8 numberOfCredentials;
u8 credentialCounter;
u8 allowListLenArr[20];
u8 allowList[20][64]; // max 20 accounts
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_I2C1_Init(void);
static void MX_I2S3_Init(void);
static void MX_SPI1_Init(void);
static void MX_RNG_Init(void);
static void MX_USART2_UART_Init(void);
/* USER CODE BEGIN PFP */
void genECDHKeyPair(void);
void genPINToken(void);
void clearPayloadData(void);
void clearSendBuf(void);
void sendCBORResponse(void);
void extractReceivedData(void);
void broadcastInit(void);
void getInfo(void);
void getPINRetries(void);
void getKeyAgreement(void);
void setPIN(void);
void changePIN(void);
void computeSharedSecret(void);
int isCorrectPIN(u8 *pinHashEnc, u8 encLen);
void getPinUvAuthToken(void);
void encodeSignature(void);
void makeCredential(void);
void getAssertion(void);
void getNextAssertion(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
PUTCHAR_PROTOTYPE
{
  /* Place your implementation of fputc here */
  /* e.g. write a character to the EVAL_COM1 and Loop until the end of transmission */
  HAL_UART_Transmit(&huart2, (uint8_t *)&ch, 1, 0xFFFF);
  return ch;
}

void genECDHKeyPair(void) {
	printf("Generating ECDH key pair... ");

	// dealing with curve params
	const ec_str_params *the_curve_const_parameters;
	ec_params curve_params;
	u8 curve_name[MAX_CURVE_NAME_LEN] = {0};

	for (int i = 0; i < EC_CURVES_NUM; i++) {
		  ec_get_curve_name_by_type(ec_maps[i].type, curve_name, sizeof(curve_name));
	}
	the_curve_const_parameters = ec_get_curve_params_by_name(curve_name, (u8)local_strnlen((const char *)curve_name, MAX_CURVE_NAME_LEN) + 1);
	import_params(&curve_params, the_curve_const_parameters);

	// generate Q = dG
	prj_pt aG;
	aff_pt aG_aff;

	a = &scalar_a;
	prj_pt_init(&aG, &(curve_params.ec_curve));
	nn_init(a, 0);
	nn_get_random_mod(a, &(curve_params.ec_gen_order));
//	nn_print("private key", a);
	prj_pt_mul_monty(&aG, a, &(curve_params.ec_gen));
	prj_pt_to_aff(&aG_aff, &aG);

	fp_export_to_buf(aG_x, 32, &(aG_aff.x));
	fp_export_to_buf(aG_y, 32, &(aG_aff.y));

	printf("Done\r\n");
//	printf("aG is on curve? %d\r\n", is_on_curve(&(aG_aff.x), &(aG_aff.y), &(curve_params.ec_curve)));
}

void genPINToken(void) {
	printf("Generating PIN Token... ");
	pinTokenLen = 16;
	for (int i = 0; i < pinTokenLen; i++) {
		pinToken[i] = 0x42;
	}
	printf("Done\r\n");
}

void clearPayloadData(void) {
	payloadOffset = 0;
	for (int i = 0; i < 1024; i++) {
		payloadData[i] = 0x0;
	}
}

void clearSendBuf(void) {
	for (int i = 0; i < 1024; i++) {
		sendBuf[i] = 0x0;
	}
}

void sendCBORResponse(void) {
	clearSendBuf();

	u8 numContinuePacket = 0;
	if (payloadOffset > 57) {
		numContinuePacket = (payloadOffset - 57 - 1) / 59 + 1;
	}

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	sendBuf[4] = 0x90;
	sendBuf[5] = payloadOffset / 256, sendBuf[6] = payloadOffset % 256;

	for (int i = 0; i < 57; i++) {
		sendBuf[7 + i] = payloadData[i];
	}
	for (int i = 0; i < numContinuePacket; i++) {
		u16 offset = 64 * (i + 1);
		for (int i = 0; i < 4; i++) {
			sendBuf[offset + i] = myCID[i];
		}
		sendBuf[offset + 4] = i;

		for (int j = 0; j < 59; j++) {
			sendBuf[offset + 5 + j] = payloadData[57 + i * 59 + j];
		}
	}

//	for (int i = 0; i < sizeof(sendBuf); i++) {
//		printf("0x%02x\r\n", sendBuf[i]);
//	}

	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64 * (1 + numContinuePacket));
}

void extractReceivedData(void) {
	for (int i = 0; i < 1024; i++) {
		receivedData[i] = 0x0;
	}

	u16 offset = 0;
	for (int i = 0; i < 57; i++) {
		receivedData[i] = receivedBuf[7 + i];
	}
	offset += 57;

	for (int i = 1; i < totalOutDataPacket; i++) {
		for (int j = 0; j < 59; j++) {
			receivedData[offset + j] = receivedBuf[i * 64 + 5 + j];
		}
		offset += 59;
	}
}

void broadcastInit(void) {
	clearSendBuf();

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = broadcastCID[i];
	}
	sendBuf[4] = 0x86;
	sendBuf[5] = 0x0, sendBuf[6] = 0x11;
	for (int i = 0; i < 8; i++) {
		sendBuf[7 + i] = receivedBuf[7 + i];
	}
	for (int i = 0; i < 4; i++) {
		sendBuf[15 + i] = myCID[i];
	}
	sendBuf[19] = 0x02, sendBuf[20] = 0x04, sendBuf[21] = 0x02, sendBuf[22] = 0x07, sendBuf[23] = 0x01 | 0x04 | 0x08;
	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
}

void getInfo(void) {
	clearPayloadData();

	payloadData[0] = 0x0;
	payloadData[1] = 0xaa;
	payloadOffset += 2;

	// version
	u8 fido2VersionString[8] = {0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30};
	u8 featureDetect[12] = {0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x31, 0x5f, 0x50, 0x52, 0x45};
	payloadData[payloadOffset] = 0x01, payloadData[payloadOffset + 1] = 0x82, payloadData[payloadOffset + 2] = 0x68;
	for (int i = 0; i < 8; i++) {
		payloadData[payloadOffset + 3 + i] = fido2VersionString[i];
	}
	payloadOffset += 11;
	payloadData[payloadOffset] = 0x6c;
	for (int i = 0; i < 12; i++) {
		payloadData[payloadOffset + 1 + i] = featureDetect[i];
	}
	payloadOffset += 1 + 12;

	// extensions
	u8 credProtect[11] = {0x63, 0x72, 0x65, 0x64, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74};
	payloadData[payloadOffset] = 0x02, payloadData[payloadOffset + 1] = 0x81, payloadData[payloadOffset + 2] = 0x6b;
	for (int i = 0; i < 11; i++) {
		payloadData[payloadOffset + 3 + i] = credProtect[i];
	}
	payloadOffset += 3 + 11;

	// aaguid
	payloadData[payloadOffset] = 0x03, payloadData[payloadOffset + 1] = 0x50;
	for (int i = 0; i < 16; i++) {
		payloadData[payloadOffset + 2 + i] = aaguid[i];
	}
	payloadOffset += 18;

	// options
	const u8 plat[4] = {0x70, 0x6c, 0x61, 0x74};
	const u8 rk[2] = {0x72, 0x6b};
	const u8 clientPin[9] = {0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x69, 0x6e};
	const u8 up[2] = {0x75, 0x70};

	payloadData[payloadOffset] = 0x04, payloadData[payloadOffset + 1] = 0xa5;
	payloadOffset += 2;

	payloadData[payloadOffset] = 0x64;
	for (int i = 0; i < 4; i++) {
		payloadData[payloadOffset + 1 + i] = plat[i];
	}
	payloadData[payloadOffset + 5] = 0xf4;
	payloadOffset += 6;

	payloadData[payloadOffset] = 0x62;
	for (int i = 0; i < 2; i++) {
		payloadData[payloadOffset + 1 + i] = rk[i];
	}
	payloadData[payloadOffset + 3] = 0xf4;
	payloadOffset += 4;

	payloadData[payloadOffset] = 0x69;
	for (int i = 0; i < 9; i++) {
		payloadData[payloadOffset + 1 + i] = clientPin[i];
	}
	payloadData[payloadOffset + 10] = 0xf4 | isSetPIN;
	payloadOffset += 11;

	payloadData[payloadOffset] = 0x62;
	for (int i = 0; i < 2; i++) {
		payloadData[payloadOffset + 1 + i] = up[i];
	}
	payloadData[payloadOffset + 3] = 0xf5;
	payloadOffset += 4;

	u8 credentialMgmt[22] = {0x75, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x4d, 0x67, 0x6d, 0x74, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77};
	for (int i = 0; i < 22; i++) {
		payloadData[payloadOffset + i] = credentialMgmt[i];
	}
	payloadData[payloadOffset + 22] = 0xf5;
	payloadOffset += 22 + 1;

	// maxMsgSize
	payloadData[payloadOffset] = 0x05;
	payloadData[payloadOffset + 1] = 0x19, payloadData[payloadOffset + 2] = 0x04, payloadData[payloadOffset + 3] = 0xb0;
	payloadOffset += 4;

	// pinUvAuthProtocols
	payloadData[payloadOffset] = 0x06, payloadData[payloadOffset + 1] = 0x81;
	payloadData[payloadOffset + 2] = 0x01;
	payloadOffset += 3;

	// maxCredentialCountInList
	payloadData[payloadOffset] = 0x07, payloadData[payloadOffset + 1] = 0x08;
	payloadOffset += 2;

	// maxCredentialIdLength
	payloadData[payloadOffset] = 0x08, payloadData[payloadOffset + 1] = 0x18, payloadData[payloadOffset + 2] = 0x80;
	payloadOffset += 3;

	// transports
	payloadData[payloadOffset] = 0x09, payloadData[payloadOffset + 1] = 0x81;
	payloadData[payloadOffset + 2] = 0x63, payloadData[payloadOffset + 3] = 0x75, payloadData[payloadOffset + 4] = 0x73, payloadData[payloadOffset + 5] = 0x62;
	payloadOffset += 6;

	// algorithms
	u8 pubKeyStr[10] = {0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79};

	payloadData[payloadOffset] = 0x0a, payloadData[payloadOffset + 1] = 0x82;
	payloadData[payloadOffset + 2] = 0xa2;
	payloadData[payloadOffset + 3] = 0x63, payloadData[payloadOffset + 4] = 0x61, payloadData[payloadOffset + 5] = 0x6c, payloadData[payloadOffset + 6] = 0x67, payloadData[payloadOffset + 7] = 0x26;
	payloadOffset += 8;
	payloadData[payloadOffset] = 0x64, payloadData[payloadOffset + 1] = 0x74, payloadData[payloadOffset + 2] = 0x79, payloadData[payloadOffset + 3] = 0x70, payloadData[payloadOffset + 4] = 0x65;
	payloadOffset += 5;
	payloadData[payloadOffset] = 0x6a;
	for (int i = 0; i < 10; i++) {
		payloadData[payloadOffset + 1 + i] = pubKeyStr[i];
	}
	payloadOffset += 1 + 10;

	payloadData[payloadOffset] = 0xa2;
	payloadData[payloadOffset + 1] = 0x63, payloadData[payloadOffset + 2] = 0x61, payloadData[payloadOffset + 3] = 0x6c, payloadData[payloadOffset + 4] = 0x67, payloadData[payloadOffset + 5] = 0x27;
	payloadOffset += 6;
	payloadData[payloadOffset] = 0x64, payloadData[payloadOffset + 1] = 0x74, payloadData[payloadOffset + 2] = 0x79, payloadData[payloadOffset + 3] = 0x70, payloadData[payloadOffset + 4] = 0x65;
	payloadOffset += 5;
	payloadData[payloadOffset] = 0x6a;
	for (int i = 0; i < 10; i++) {
		payloadData[payloadOffset + 1 + i] = pubKeyStr[i];
	}
	payloadOffset += 1 + 10;

	sendCBORResponse();
}

void getPINRetries(void) {
	clearPayloadData();

	payloadData[0] = 0x0;
	payloadData[1] = 0xa1;
	payloadData[2] = 0x03;
	payloadData[3] = pinRetries;
	payloadOffset += 4;

	sendCBORResponse();
}

void getKeyAgreement(void) {
	clearPayloadData();

	payloadData[0] = 0x0;
	payloadData[1] = 0xa1, payloadData[2] = 0x01;
	payloadOffset += 3;
	payloadData[payloadOffset] = 0xa5;
	payloadData[payloadOffset + 1] = 0x01, payloadData[payloadOffset + 2] = 0x02;
	payloadData[payloadOffset + 3] = 0x03, payloadData[payloadOffset + 4] = 0x26;
	payloadData[payloadOffset + 5] = 0x20, payloadData[payloadOffset + 6] = 0x01;
	payloadOffset += 7;
	payloadData[payloadOffset] = 0x21, payloadData[payloadOffset + 1] = 0x58, payloadData[payloadOffset + 2] = 0x20;
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + 3 + i] = aG_x[i];
	}
	payloadOffset += 35;
	payloadData[payloadOffset] = 0x22, payloadData[payloadOffset + 1] = 0x58, payloadData[payloadOffset + 2] = 0x20;
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + 3 + i] = aG_y[i];
	}
	payloadOffset += 35;

	sendCBORResponse();
}

void setPIN(void) {
	// get platform public key
	for (int i = 0; i < 32; i++) {
		bG_x[i] = receivedBuf[i + 25];
	}
	for (int i = 0; i < 4; i++) {
		bG_y[i] = receivedBuf[i + 60];
	}
	for (int i = 4; i < 32; i++) {
		bG_y[i] = receivedBuf[i + 65];
	}

	// get pin uv auth
	u8 pinUvAuth[16];
	for (int i = 0; i < 16; i++) {
		pinUvAuth[i] = receivedBuf[99 + i];
	}

	// get new pin enc
	u8 newPINEnc[64];
	for (int i = 0; i < 10; i++) {
		newPINEnc[i] = receivedBuf[118 + i];
	}
	for (int i = 10; i < 64; i++) {
		newPINEnc[i] = receivedBuf[123 + i];
	}

	// after receive data
	clearSendBuf();
	clearPayloadData();

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	sendBuf[4] = 0x90;
	sendBuf[5] = 0x0, sendBuf[6] = 0x01;

	if (isSetPIN) {
		sendBuf[7] = 0x33;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		return;
	}

	computeSharedSecret();

	// verify hmac
	u8 hmacOutcome[100];

	hmac_sha256(hmacOutcome, newPINEnc, 64, sharedSecret, 32);
	u8 isCorrectHmac = 1;
	for (int i = 0; i < 16; i++) {
		isCorrectHmac &= (pinUvAuth[i] == hmacOutcome[i]);
	}
	if (!isCorrectHmac) {
		printf("inCorrect hmac\r\n");
		sendBuf[7] = 0x33;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		return;
	}

	// decrypt new PIN
	struct AES_ctx aes_ctx;
	u8 newPIN[100];

	for (int i = 0; i < 64; i++) {
		newPIN[i] = newPINEnc[i];
	}
	AES_init_ctx_iv(&aes_ctx, sharedSecret, initialVector);
	AES_CBC_decrypt_buffer(&aes_ctx, newPIN, 64);

	// extract the new PIN
	u8 newPINLen = 64;
	for (int i = 0; i < 64; i++) {
		if (newPIN[i] == 0x0) {
			newPINLen = i;
			break;
		}
	}

	// hash the new PIN
	sha256_context hash_ctx;
	u8 newPINHash[32];

	for (int i = 0; i < 32; i++) {
		newPINHash[i] = 0x0;
	}
	sha256_init(&hash_ctx);
	sha256_update(&hash_ctx, newPIN, newPINLen);
	sha256_final(&hash_ctx, newPINHash);
	for (int i = 0; i < 16; i++) {
		pinHash[i] = newPINHash[i];
	}

	sendBuf[7] = 0x0;
	pinRetries = retriesMax;
	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
	isSetPIN = 1;
	return;

}

void changePIN(void) {
	/* parse received data */

	// get platform public key
	for (int i = 0; i < 32; i++) {
		bG_x[i] = receivedBuf[i + 25];
	}
	for (int i = 0; i < 4; i++) {
		bG_y[i] = receivedBuf[i + 60];
	}
	for (int i = 4; i < 32; i++) {
		bG_y[i] = receivedBuf[i + 65];
	}

	// get pin uv auth
	u8 pinUvAuth[16];
	for (int i = 0; i < 16; i++) {
		pinUvAuth[i] = receivedBuf[99 + i];
	}

	// get new pin enc
	u8 newPINEnc[64];
	for (int i = 0; i < 10; i++) {
		newPINEnc[i] = receivedBuf[118 + i];
	}
	for (int i = 10; i < 64; i++) {
		newPINEnc[i] = receivedBuf[123 + i];
	}

	// get cur pin enc
	u8 curPINEnc[16];
	for (int i = 0; i < 3; i++) {
		curPINEnc[i] = receivedBuf[189 + i];
	}
	for (int i = 3; i < 16; i++) {
		curPINEnc[i] = receivedBuf[194 + i];
	}


	/* after parsing received data */
	clearSendBuf();
	clearPayloadData();

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	sendBuf[4] = 0x90;
	sendBuf[5] = 0x0, sendBuf[6] = 0x01;

	if (pinRetries == 0) {
		sendBuf[7] = 0x32;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		return;
	}

	computeSharedSecret();

	// compute and verify pinUvAuth
	u8 hmacOutcome[100];
	u8 msg[100];

	for (int i = 0; i < 64; i++) {
		msg[i] = newPINEnc[i];
	}
	for (int i = 0; i < 16; i++) {
		msg[64 + i] = curPINEnc[i];
	}
	hmac_sha256(hmacOutcome, msg, 64 + 16, sharedSecret, 32);
	u8 isCorrectHmac = 1;
	for (int i = 0; i < 16; i++) {
		isCorrectHmac &= (pinUvAuth[i] == hmacOutcome[i]);
	}
	if (!isCorrectHmac) {
		sendBuf[7] = 0x33;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		return;
	}

	pinRetries -= 1;

	// check PIN
	if (!isCorrectPIN(curPINEnc, 16)) {
		genECDHKeyPair();
		consecutivePinErr += 1;
		if (consecutivePinErr == 3 - 1) {
			sendBuf[7] = 0x34;
			USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
			return;
		}
		else {
			sendBuf[7] = 0x31;
			USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
			return;
		}
	}

	pinRetries = retriesMax;

	// decrypt the new pin enc
	struct AES_ctx aes_ctx;
	u8 newPIN[100];

	for (int i = 0; i < 64; i++) {
		newPIN[i] = newPINEnc[i];
	}
	AES_init_ctx_iv(&aes_ctx, sharedSecret, initialVector);
	AES_CBC_decrypt_buffer(&aes_ctx, newPIN, 64);

	// extract the new PIN
	u8 newPINLen = 64;
	for (int i = 0; i < 64; i++) {
		if (newPIN[i] == 0x0) {
			newPINLen = i;
			break;
		}
	}

	if (newPINLen < 4) {
		sendBuf[7] = 0x37;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		return;
	}

	// hash the new PIN
	sha256_context hash_ctx;
	u8 newPINHash[32];

	for (int i = 0; i < 32; i++) {
		newPINHash[i] = 0x0;
	}
	sha256_init(&hash_ctx);
	sha256_update(&hash_ctx, newPIN, newPINLen);
	sha256_final(&hash_ctx, newPINHash);
	for (int i = 0; i < 16; i++) {
		pinHash[i] = newPINHash[i];
	}

	genPINToken();

	sendBuf[7] = 0x0;
	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
	return;
}

void computeSharedSecret(void) {
	// dealing with curve params
	const ec_str_params *the_curve_const_parameters;
	ec_params curve_params;
	u8 curve_name[MAX_CURVE_NAME_LEN] = {0};

	for (int i = 0; i < EC_CURVES_NUM; i++) {
		  ec_get_curve_name_by_type(ec_maps[i].type, curve_name, sizeof(curve_name));
	}
	the_curve_const_parameters = ec_get_curve_params_by_name(curve_name, (u8)local_strnlen((const char *)curve_name, MAX_CURVE_NAME_LEN) + 1);
	import_params(&curve_params, the_curve_const_parameters);

	// import bG
	prj_pt bG;
	aff_pt bG_aff;

	aff_pt_init(&bG_aff, &(curve_params.ec_curve));
	fp_import_from_buf(&(bG_aff.x), bG_x, 32);
	fp_import_from_buf(&(bG_aff.y), bG_y, 32);
	ec_shortw_aff_to_prj(&(bG), &(bG_aff));
//	printf("bG is on curve? %d\r\n", prj_pt_is_on_curve(&(bG)));

	// compute abG
	prj_pt abG;
	aff_pt abG_aff;
	prj_pt_mul_monty(&abG, a, &bG);
	prj_pt_to_aff(&abG_aff, &abG);
	fp_export_to_buf(abG_x, 32, &(abG_aff.x));

	// compute shared secret = sha256(abG_x)
	sha256_context ctx;

	for (int i = 0; i < 32; i++) {
		sharedSecret[i] = 0x0;
	}
	sha256_init(&ctx);
	sha256_update(&ctx, abG_x, 32);
	sha256_final(&ctx, sharedSecret);
}

int isCorrectPIN(u8 *pinHashEnc, u8 encLen) {
	struct AES_ctx ctx;
	u8 buf[1024] = {0x0};

	for (int i = 0; i < encLen; i++) {
		buf[i] = pinHashEnc[i];
	}
	// Decryption
	AES_init_ctx_iv(&ctx, sharedSecret, initialVector);
	AES_CBC_decrypt_buffer(&ctx, buf, encLen);

	// Check
	int ret = 1;
	for (int i = 0; i < 16; i++) {
		ret &= (pinHash[i] == buf[i]);
	}

	return ret;
}

void getPinUvAuthToken(void) {
	clearSendBuf();
	clearPayloadData();

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	sendBuf[4] = 0x90;
	sendBuf[5] = 0x0, sendBuf[6] = 0x01;

	// get platform public key
	for (int i = 0; i < 32; i++) {
		bG_x[i] = receivedBuf[i + 25];
	}
	for (int i = 0; i < 4; i++) {
		bG_y[i] = receivedBuf[i + 60];
	}
	for (int i = 4; i < 32; i++) {
		bG_y[i] = receivedBuf[i + 65];
	}

	// get pinHashEnc
	u8 encryptedPINHash[16] = {0x0};
	for (int i = 0; i < 16; i++) {
		encryptedPINHash[i] = receivedBuf[99 + i];
	}

	printf("PIN Retries: %u\r\n", pinRetries);

	if (pinRetries == 0) {
		sendBuf[7] = 0x32;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		return;
	}

	computeSharedSecret();
	pinRetries -= 1;

	if (!isCorrectPIN(encryptedPINHash, 16)) {
		genECDHKeyPair();
		consecutivePinErr += 1;
		if (consecutivePinErr == 3 - 1) {
			sendBuf[7] = 0x34;
			USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
			return;
		}
		else {
			sendBuf[7] = 0x31;
			USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
			return;
		}
	}

	pinRetries = retriesMax;
	consecutivePinErr = 0;

	// Encrypt pinToken
	struct AES_ctx ctx;
	u8 buf[1024] = {0x0};

	for (int i = 0; i < pinTokenLen; i++) {
		buf[i] = pinToken[i];
	}
	AES_init_ctx_iv(&ctx, sharedSecret, initialVector);
	AES_CBC_encrypt_buffer(&ctx, buf, pinTokenLen);

	payloadData[0] = 0x0;
	payloadData[1] = 0xa1, payloadData[2] = 0x02;
	payloadData[3] = 0x50;
	payloadOffset += 4;
	for (int i = 0; i < pinTokenLen; i++) {
		payloadData[payloadOffset + i] = buf[i];
	}
	payloadOffset += 16;
	sendCBORResponse();
	return;
}

void encodeSignature(void) {
  const u8 check = 0x80;
  u8 sigROffset = 0, sigSOffset = 0;

  encodedSig[0] = 0x30;
  encodedSig[2] = 0x02;
  if (my_sig_r[0] & check) {
    sigROffset = 1;
    encodedSig[4] = 0x0;
  }

  encodedSig[3] = 0x20 + sigROffset;
  for (int i = 0; i < 32; i++) {
    encodedSig[4 + sigROffset + i] = my_sig_r[i];
  }
  encodedSig[4 + sigROffset + 32] = 0x02;
  if (my_sig_s[0] & check) {
    sigSOffset = 1;
    encodedSig[6 + sigROffset + 32] = 0x0;
  }

  encodedSig[5 + sigROffset + 32] = 0x20 + sigSOffset;
  for (int i = 0; i < 32; i++) {
    encodedSig[6 + sigROffset + sigSOffset + 32 + i] = my_sig_s[i];
  }
  encodedSig[1] = 4 + 64 + sigROffset + sigSOffset;
  encodedSigLen = 70 + sigROffset + sigSOffset;
}

void makeCredential(void) {
	clearSendBuf();
	extractReceivedData();

	u8 len;
	u16 offset = 0;

	// client data hash
	for (int i = 0; i < 32; i++) {
		clientDataHash[i] = receivedData[5 + i];
	}

	offset += 5 + 32 + 5;

	// rp id
	if (receivedData[offset] == 0x78) {
		rpIDLen = receivedData[offset + 1];
		offset += 2;
	}
	else {
		rpIDLen = receivedData[offset] & 31;
		offset += 1;
	}
	for (int i = 0; i < rpIDLen; i++) {
		rpID[i] = receivedData[offset + i];
	}

	offset += rpIDLen + 5;

	// rp name
	if (receivedData[offset] == 0x78) {
		len = receivedData[offset + 1];
		offset += 2;
	}
	else {
		len = receivedData[offset] & 31;
		offset += 1;
	}

	offset += len + 5;

	// user id
	if (receivedData[offset] == 0x58) {
		userIDLen = receivedData[offset + 1];
		offset += 2;
	}
	else {
		userIDLen = receivedData[offset] & 31;
		offset += 1;
	}
	for (int i = 0; i < userIDLen; i++) {
		userID[i] = receivedData[offset + i];
	}

	offset += userIDLen + 5;

	// user name
	if (receivedData[offset] == 0x78) {
		len = receivedData[offset + 1];
		offset += 2;
	}
	else {
		len = receivedData[offset] & 31;
		offset += 1;
	}

	offset += len + 12;

	// user display name
	if (receivedData[offset] == 0x78) {
		len = receivedData[offset + 1];
		offset += 2;
	}
	else {
		len = receivedData[offset] & 31;
		offset += 1;
	}

//	printf("rp id:\r\n");
//	for (int i = 0; i < rpIDLen; i++) {
//		printf("%02x", rpID[i]);
//	}
//	printf("\r\n");
//	printf("user id:\r\n");
//	for (int i = 0; i < userIDLen; i++) {
//		printf("%02x", userID[i]);
//	}
//	printf("\r\n");

	offset += len + 1;

	// public key credential parameters
	u8 arrayItems = receivedData[offset] & 31;
	offset += 1;
	for (int i = 0; i < arrayItems; i++) {
		offset += 5;
		if (receivedData[offset] == 0x38) {
			offset += 2;
		}
		else if (receivedData[offset] == 0x39) {
			offset += 3;
		}
		else {
			offset += 1;
		}
		offset += 5 + 11;
	}

	offset += 1;

	// pinUvAuth
	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	sendBuf[4] = 0x90;
	sendBuf[5] = 0x0, sendBuf[6] = 0x01;
	if (receivedData[offset] == 0x40) {
		if (isSetPIN) {
			sendBuf[7] = 0x31;
			USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		}
		else {
			sendBuf[7] = 0x35;
			USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		}
		return;
	}
	offset += 1;

	u8 pinUvAuth[16];
	for (int i = 0; i < 16; i++) {
		pinUvAuth[i] = receivedData[offset + i];
	}


	/* after parse receive data */
	u8 flags = 64; // 0b01000000

	clearPayloadData();
	clearSendBuf();

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	sendBuf[4] = 0xbb;
	sendBuf[5] = 0x0, sendBuf[6] = 0x01, sendBuf[7] = 0x02;

	while (HAL_GPIO_ReadPin(GPIOA,GPIO_PIN_0) != GPIO_PIN_SET) {
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		HAL_Delay(100);
	}
	flags |= 0x01;

	HAL_Delay(150);
	sendBuf[7] = 0x01;
	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);


	// verify hmac
	u8 hmacOutcome[100];

	hmac_sha256(hmacOutcome, clientDataHash, 32, pinToken, pinTokenLen);
	u8 isCorrectHmac = 1;
	for (int i = 0; i < 16; i++) {
		isCorrectHmac &= (pinUvAuth[i] == hmacOutcome[i]);
	}
	if (isCorrectHmac) {
		printf("Correct hmac\r\n");
		flags |= 0x04;
	}
	else {
		printf("wrong hmac\r\n");
		sendBuf[4] = 0x90;
		sendBuf[5] = 0x0, sendBuf[6] = 0x01, sendBuf[7] = 0x33;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		return;
	}

	// gen user key pair
	printf("Gen user key... ");
	int ret = my_gen_key_pair();
	if (ret) {
		printf("fail on my_gen_key_pair!\r\n");
	}
	else {
		printf("done\r\n");
	}

	// hash the rpID
	sha256_context ctx;
	u8 rpIDHash[32];

	for (int i = 0; i < 32; i++) {
		rpIDHash[i] = 0x0;
	}
	sha256_init(&ctx);
	sha256_update(&ctx, rpID, rpIDLen);
	sha256_final(&ctx, rpIDHash);

	// signCount
	u8 signCountArr[4];
	signCountArr[0] = signCount & 0xff;
	signCountArr[1] = signCount & 0xff00;
	signCountArr[2] = signCount & 0xff0000;
	signCountArr[3] = signCount & 0xff000000;

	// credential ID = sha256(rpID | userID)
	u8 credentialIDLen[2] = {0x0, 0x20};
	u8 credentialID[32];
	u8 keyhandleMaterial[1024];
	sha256_context ctxKeyHandle;

	for (int i = 0; i < rpIDLen; i++) {
		keyhandleMaterial[i] = rpID[i];
	}
	for (int i = rpIDLen; i < rpIDLen + userIDLen; i++) {
		keyhandleMaterial[i] = userID[i];
	}
	for (int i = 0; i < credentialIDLen[1]; i++) {
		credentialID[i] = 0x0;
	}
	sha256_init(&ctxKeyHandle);
	sha256_update(&ctxKeyHandle, keyhandleMaterial, rpIDLen + userIDLen);
	sha256_final(&ctxKeyHandle, credentialID);

	// signature
	u8 msg[255] = {0};
	u8 msglen = 162;
	for (int i = 0; i < 32; i++) {
		msg[1 + i] = rpIDHash[i]; // app parameters
	}
	for (int i = 0; i < 32; i++) {
		msg[1 + 32 + i] = clientDataHash[i]; // challenge parameters
	}
	for (int i = 0; i < 32; i++) {
		msg[1 + 32 + 32 + i] = credentialID[i]; // key handle
	}
	msg[1 + 32 + 32 + 32 + 1] = 0x04; // uncompressed form
	for (int i = 0; i < 64; i++) {
	  msg[1 + 32 + 32 + 32 + 1 + i] = my_pub_key[i];
	}

	printf("Performing signature... ");
	ret = my_sign("ECDSA", "SHA256", "SECP256R1", msg, msglen, 0);
	if (ret) {
	  printf("Error at signing\r\n");
	}
	else {
		printf("done\r\n");
	}
	encodeSignature();

	// payload data
	payloadData[0] = 0x0;
	payloadData[1] = 0xa3;
	payloadData[2] = 0x01, payloadData[3] = 0x66;
	payloadData[4] = 0x70, payloadData[5] = 0x61, payloadData[6] = 0x63, payloadData[7] = 0x6b, payloadData[8] = 0x65, payloadData[9] = 0x64;
	payloadOffset += 10;
	payloadData[payloadOffset] = 0x02, payloadData[payloadOffset + 1] = 0x58, payloadData[payloadOffset + 2] = 0xa4; // BCNT = 164
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + 3 + i] = rpIDHash[i];
	}
	payloadOffset += 35;
	payloadData[payloadOffset] = flags;
	payloadOffset += 1;
	for (int i = 0; i < 4; i++) {
		payloadData[payloadOffset + i] = signCountArr[i];
	}
	payloadOffset += 4;
	for (int i = 0; i < 16; i++) {
		payloadData[payloadOffset + i] = aaguid[i];
	}
	payloadOffset += 16;
	payloadData[payloadOffset] = credentialIDLen[0], payloadData[payloadOffset + 1] = credentialIDLen[1];
	payloadOffset += 2;
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + i] = credentialID[i];
	}
	payloadOffset += 32;
	payloadData[payloadOffset] = 0xa5;
	payloadData[payloadOffset + 1] = 0x01, payloadData[payloadOffset + 2] = 0x02;
	payloadData[payloadOffset + 3] = 0x03, payloadData[payloadOffset + 4] = 0x26;
	payloadData[payloadOffset + 5] = 0x20, payloadData[payloadOffset + 6] = 0x01;
	payloadOffset += 7;
	payloadData[payloadOffset] = 0x21, payloadData[payloadOffset + 1] = 0x58, payloadData[payloadOffset + 2] = 0x20;
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + 3 + i] = my_pub_key[i];
	}
	payloadOffset += 35;
	payloadData[payloadOffset] = 0x22, payloadData[payloadOffset + 1] = 0x58, payloadData[payloadOffset + 2] = 0x20;
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + 3 + i] = my_pub_key[32 + i];
	}
	payloadOffset += 35;

	payloadData[payloadOffset] = 0x03;
	payloadData[payloadOffset + 1] = 0xa3;

	payloadData[payloadOffset + 2] = 0x63, payloadData[payloadOffset + 3] = 0x61, payloadData[payloadOffset + 4] = 0x6c, payloadData[payloadOffset + 5] = 0x67, payloadData[payloadOffset + 6] = 0x26;
	payloadOffset += 7;
	payloadData[payloadOffset] = 0x63, payloadData[payloadOffset + 1] = 0x73, payloadData[payloadOffset + 2] = 0x69, payloadData[payloadOffset + 3] = 0x67;
	payloadData[payloadOffset + 4] = 0x58, payloadData[payloadOffset + 5] = encodedSigLen;
	payloadOffset += 6;
	for (int i = 0; i < encodedSigLen; i++) {
		payloadData[payloadOffset + i] = encodedSig[i];
	}
	payloadOffset += encodedSigLen;
	payloadData[payloadOffset] = 0x63, payloadData[payloadOffset + 1] = 0x78, payloadData[payloadOffset + 2] = 0x35, payloadData[payloadOffset + 3] = 0x63;
	payloadData[payloadOffset + 4] = 0x81, payloadData[payloadOffset + 5] = 0x59, payloadData[payloadOffset + 6] = 0x02, payloadData[payloadOffset + 7] = 0x2f;
	payloadOffset += 8;
	for (int i = 0; i < att_len; i++) {
		payloadData[payloadOffset + i] = att[i];
	}
	payloadOffset += att_len;

	sendCBORResponse();
}

void getAssertion(void) {
	clearSendBuf();
	extractReceivedData();

	u8 offset = 0;
	u8 parameters = receivedData[1] & 31;

	offset += 3;

	// rp id
	if (receivedData[offset] == 0x78) {
		rpIDLen = receivedData[offset + 1];
		offset += 2;
	}
	else {
		rpIDLen = receivedData[offset] & 31;
		offset += 1;
	}
	for (int i = 0; i < rpIDLen; i++) {
		rpID[i] = receivedData[offset + i];
	}
	offset += rpIDLen + 3;

	// clientDataHash
	for (int i = 0; i < 32; i++) {
		clientDataHash[i] = receivedData[offset + i];
	}
	offset += 32 + 1;

	// allow list
	credentialCounter = 0; // only for numberOfCredentials > 1

	for (int i = 0; i < 20; i++) {
		allowListLenArr[i] = 0x0;
		for (int j = 0; j < 64; j++) {
			allowList[i][j] = 0x0;
		}
	}

	if (receivedData[offset] == 0x98) {
		numberOfCredentials = receivedData[offset + 1];
		offset += 2;
		credentialCounter = 1;
	}
	else {
		numberOfCredentials = receivedData[offset] & 31;
		offset += 1;
	}
	for (int i = 0; i < numberOfCredentials; i++) {
		offset += 5;
		allowListLenArr[i] = receivedData[offset];
		offset += 1;

		for (int j = 0; j < allowListLenArr[i]; j++) {
			allowList[i][j] = receivedData[offset + j];
		}
	}


	/* debug received data */
//	printf("getAssertion: rpID = ");
//	for (int i = 0; i < rpIDLen; i++) {
//		printf("%02x ", rpID[i]);
//	}
//	printf("\r\n");
//
//	printf("getAssertion: client data hash = ");
//	for (int i = 0; i < 32; i++) {
//		printf("%02x ", clientDataHash[i]);
//	}
//	printf("\r\n");
//
//	printf("getAssertion: allow list:\r\n");
//	for (int i = 0; i < numberOfCredentials; i++) {
//		printf("index 0x%02x: ", allowListLenArr[i]);
//		for (int j = 0; j < allowListLenArr[i]; j++) {
//			printf("%02x", allowList[i][j]);
//		}
//		printf("\r\n");
//	}

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	// up message
	sendBuf[4] = 0xbb;
	sendBuf[5] = 0x0, sendBuf[6] = 0x01, sendBuf[7] = 0x02;
	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);

	u8 userPresence = 0x0;
	while (HAL_GPIO_ReadPin(GPIOA,GPIO_PIN_0) != GPIO_PIN_SET) {
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
		HAL_Delay(100);
	}
	userPresence |= 0x01;

	// waiting message
	HAL_Delay(150);
	sendBuf[7] = 0x01;
	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);

	/* payload data */
	clearPayloadData();

	payloadData[0] = 0x0;
	payloadData[1] = 0xa3 | (numberOfCredentials > 1);
	payloadData[2] = 0x01, payloadData[3] = 0xa2, payloadData[4] = 0x62, payloadData[5] = 0x69, payloadData[6] = 0x64;
	payloadOffset += 7;
	payloadData[payloadOffset] = 0x58, payloadData[payloadOffset + 1] = 0x20;
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + 2 + i] = allowList[0][i];
	}
	payloadOffset += 2 + 32;
	payloadData[payloadOffset] = 0x64, payloadData[payloadOffset + 1] = 0x74, payloadData[payloadOffset + 2] = 0x79, payloadData[payloadOffset + 3] = 0x70, payloadData[payloadOffset + 4] = 0x65;
	payloadData[payloadOffset + 5] = 0x6a;
	payloadOffset += 6;
	u8 pubKeyStr[10] = {0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79};
	for (int i = 0; i < 10; i++) {
		payloadData[payloadOffset + i] = pubKeyStr[i];
	}
	payloadOffset += 10;

	/* auth data */
	u8 authData[37];
	for (int i = 0; i < 37; i++) {
		authData[i] = 0x0;
	}

	// hash the rpID
	sha256_context ctx;
	u8 rpIDHash[32];

	for (int i = 0; i < 32; i++) {
		rpIDHash[i] = 0x0;
	}
	sha256_init(&ctx);
	sha256_update(&ctx, rpID, rpIDLen);
	sha256_final(&ctx, rpIDHash);

	// sign count
	signCount += 1;
	u8 signCountArr[4];
	signCountArr[0] = signCount & 0xff;
	signCountArr[1] = signCount & 0xff00;
	signCountArr[2] = signCount & 0xff0000;
	signCountArr[3] = signCount & 0xff000000;

	for (int i = 0; i < 32; i++) {
		authData[i] = rpIDHash[i];
	}
	authData[32] = userPresence;
	for (int i = 0; i < 4; i++) {
		authData[32 + 1 + i] = signCountArr[i];
	}

	payloadData[payloadOffset] = 0x02, payloadData[payloadOffset + 1] = 0x58, payloadData[payloadOffset + 2] = 0x25;
	payloadOffset += 3;
	for (int i = 0; i < 37; i++) {
		payloadData[payloadOffset + i] = authData[i];
	}
	payloadOffset += 37;

	/* signature */
	u8 msg[255] = {0};
	u8 msglen = 69;
	for (int i = 0; i < 32; i++) {
		msg[i] = rpIDHash[i]; // app parameters
	}
	for (int i = 0; i < 32; i++) {
		msg[32 + 1 + 4 + i] = clientDataHash[i]; // challenge parameters
	}
	msg[32] = userPresence;
	for (int i = 0; i < 4; i++) {
		msg[32 + 1 + i] = signCountArr[i];
	}

	printf("Performing signature... ");
	int ret = my_sign("ECDSA", "SHA256", "SECP256R1", msg, msglen, 1);
	if (ret) {
	  printf("Error at signing\r\n");
	}
	else {
		printf("done\r\n");
	}
	encodeSignature();

	payloadData[payloadOffset] = 0x03, payloadData[payloadOffset + 1] = 0x58;
	payloadData[payloadOffset + 2] = encodedSigLen;
	payloadOffset += 3;
	for (int i = 0; i < encodedSigLen; i++) {
		payloadData[payloadOffset + i] = encodedSig[i];
	}
	payloadOffset += encodedSigLen;

	// number of credentials (optional)
	if (numberOfCredentials > 1) {
		payloadData[payloadOffset] = 0x05;
		if (numberOfCredentials <= 23) {
			payloadData[payloadOffset + 1] = numberOfCredentials;
			payloadOffset += 2;
		}
		else if (numberOfCredentials <= 255) {
			payloadData[payloadOffset + 1] = 0x18;
			payloadData[payloadOffset + 2] = numberOfCredentials;
			payloadOffset += 3;
		}
		else {
			printf("Too many credential to handle!\r\n");
		}
	}

	sendCBORResponse();
}

void getNextAssertion(void) {
	clearSendBuf();

	for (int i = 0; i < 4; i++) {
		sendBuf[i] = myCID[i];
	}
	sendBuf[4] = 0x90;
	sendBuf[5] = 0x0, sendBuf[6] = 0x01;

	if (credentialCounter >= numberOfCredentials) {
		sendBuf[7] = 0x30;
		USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);
	}

	// the waiting message
	HAL_Delay(150);
	sendBuf[7] = 0x01;
	USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, sendBuf, 64);

	/* payload data */
	clearPayloadData();

	payloadData[0] = 0x0;
	payloadData[1] = 0xa3;
	payloadData[2] = 0x01, payloadData[3] = 0xa2, payloadData[4] = 0x62, payloadData[5] = 0x69, payloadData[6] = 0x64;
	payloadOffset += 7;
	payloadData[payloadOffset] = 0x58, payloadData[payloadOffset + 1] = 0x20;
	for (int i = 0; i < 32; i++) {
		payloadData[payloadOffset + 2 + i] = allowList[credentialCounter][i];
	}
	payloadOffset += 2 + 32;
	payloadData[payloadOffset] = 0x64, payloadData[payloadOffset + 1] = 0x74, payloadData[payloadOffset + 2] = 0x79, payloadData[payloadOffset + 3] = 0x70, payloadData[payloadOffset + 4] = 0x65;
	payloadData[payloadOffset + 5] = 0x6a;
	payloadOffset += 6;
	u8 pubKeyStr[10] = {0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79};
	for (int i = 0; i < 10; i++) {
		payloadData[payloadOffset + i] = pubKeyStr[i];
	}
	payloadOffset += 10;

	/* auth data */
	u8 authData[37];
	for (int i = 0; i < 37; i++) {
		authData[i] = 0x0;
	}

	// hash the rpID
	sha256_context ctx;
	u8 rpIDHash[32];

	for (int i = 0; i < 32; i++) {
		rpIDHash[i] = 0x0;
	}
	sha256_init(&ctx);
	sha256_update(&ctx, rpID, rpIDLen);
	sha256_final(&ctx, rpIDHash);

	// sign count
	u8 individualSignCnt = 1; // There are some problems in this step
	u8 signCountArr[4];
	signCountArr[0] = individualSignCnt & 0xff;
	signCountArr[1] = individualSignCnt & 0xff00;
	signCountArr[2] = individualSignCnt & 0xff0000;
	signCountArr[3] = individualSignCnt & 0xff000000;

	for (int i = 0; i < 32; i++) {
		authData[i] = rpIDHash[i];
	}
	authData[32] = 0x01; // up
	for (int i = 0; i < 4; i++) {
		authData[32 + 1 + i] = signCountArr[i];
	}

	payloadData[payloadOffset] = 0x02, payloadData[payloadOffset + 1] = 0x58, payloadData[payloadOffset + 2] = 0x25;
	payloadOffset += 3;
	for (int i = 0; i < 37; i++) {
		payloadData[payloadOffset + i] = authData[i];
	}
	payloadOffset += 37;

	/* signature */
	u8 msg[255] = {0};
	u8 msglen = 69;
	for (int i = 0; i < 32; i++) {
		msg[i] = rpIDHash[i]; // app parameters
	}
	for (int i = 0; i < 32; i++) {
		msg[32 + 1 + 4 + i] = clientDataHash[i]; // challenge parameters
	}
	msg[32] = 0x01; // up
	for (int i = 0; i < 4; i++) {
		msg[32 + 1 + i] = signCountArr[i];
	}

	printf("Performing signature... ");
	int ret = my_sign("ECDSA", "SHA256", "SECP256R1", msg, msglen, 1);
	if (ret) {
	  printf("Error at signing\r\n");
	}
	else {
		printf("done\r\n");
	}
	encodeSignature();

	payloadData[payloadOffset] = 0x03, payloadData[payloadOffset + 1] = 0x58;
	payloadData[payloadOffset + 2] = encodedSigLen;
	payloadOffset += 3;
	for (int i = 0; i < encodedSigLen; i++) {
		payloadData[payloadOffset + i] = encodedSig[i];
	}
	payloadOffset += encodedSigLen;

	credentialCounter++;
	sendCBORResponse();
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_I2C1_Init();
  MX_I2S3_Init();
  MX_SPI1_Init();
  MX_RNG_Init();
  MX_USART2_UART_Init();
  MX_USB_DEVICE_Init();
  /* USER CODE BEGIN 2 */
  printf("It's in main function!!!\r\n");

  totalOutDataPacket = 0;
  nowOutDataPacket = 0;

  isSetPIN = 1;
  pinRetries = retriesMax;

  genECDHKeyPair();
  genPINToken();
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1) {
	  if (totalOutDataPacket && nowOutDataPacket == totalOutDataPacket) {
		  if (receivedBuf[0] == broadcastCID[0] && receivedBuf[1] == broadcastCID[1] && receivedBuf[2] == broadcastCID[2] && receivedBuf[3] == broadcastCID[3]) {
			  if (receivedBuf[4] == 0x86) {
				  broadcastInit();
			  }
		  }
		  else if (receivedBuf[0] == myCID[0] && receivedBuf[1] == myCID[1] && receivedBuf[2] == myCID[2] && receivedBuf[3] == myCID[3]) {
			  if (receivedBuf[4] == 0x90) {
				  if (receivedBuf[7] == 0x04) {
					  getInfo();
				  }
				  else if (receivedBuf[7] == 0x06) {
					  if (receivedBuf[12] == 0x01) {
						  getPINRetries();
					  }
					  else if (receivedBuf[12] == 0x02) {
						  getKeyAgreement();
					  }
					  else if (receivedBuf[12] == 0x03) {
						  setPIN();
					  }
					  else if (receivedBuf[12] == 0x04) {
						  changePIN();
					  }
					  else if (receivedBuf[12] == 0x05) {
						  getPinUvAuthToken();
					  }
				  }
				  else if (receivedBuf[7] == 0x01) {
					  makeCredential();
				  }
				  else if (receivedBuf[7] == 0x02) {
					  getAssertion();
				  }
				  else if (receivedBuf[7] == 0x08) {
					  getNextAssertion();
				  }
			  }
			  else {
				  printf("Unknown CTAPHID command\r\n");
			  }
		  }
		  else {
			  printf("Error CID\r\n");
		  }

		  nowOutDataPacket = 0;
		  totalOutDataPacket = 0;
	}
	HAL_Delay(5);
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_PeriphCLKInitTypeDef PeriphClkInitStruct = {0};

  /** Configure the main internal regulator output voltage 
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
  /** Initializes the CPU, AHB and APB busses clocks 
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /** Initializes the CPU, AHB and APB busses clocks 
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
  PeriphClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_I2S;
  PeriphClkInitStruct.PLLI2S.PLLI2SN = 192;
  PeriphClkInitStruct.PLLI2S.PLLI2SR = 2;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief I2C1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2C1_Init(void)
{

  /* USER CODE BEGIN I2C1_Init 0 */

  /* USER CODE END I2C1_Init 0 */

  /* USER CODE BEGIN I2C1_Init 1 */

  /* USER CODE END I2C1_Init 1 */
  hi2c1.Instance = I2C1;
  hi2c1.Init.ClockSpeed = 100000;
  hi2c1.Init.DutyCycle = I2C_DUTYCYCLE_2;
  hi2c1.Init.OwnAddress1 = 0;
  hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c1.Init.OwnAddress2 = 0;
  hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2C1_Init 2 */

  /* USER CODE END I2C1_Init 2 */

}

/**
  * @brief I2S3 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2S3_Init(void)
{

  /* USER CODE BEGIN I2S3_Init 0 */

  /* USER CODE END I2S3_Init 0 */

  /* USER CODE BEGIN I2S3_Init 1 */

  /* USER CODE END I2S3_Init 1 */
  hi2s3.Instance = SPI3;
  hi2s3.Init.Mode = I2S_MODE_MASTER_TX;
  hi2s3.Init.Standard = I2S_STANDARD_PHILIPS;
  hi2s3.Init.DataFormat = I2S_DATAFORMAT_16B;
  hi2s3.Init.MCLKOutput = I2S_MCLKOUTPUT_ENABLE;
  hi2s3.Init.AudioFreq = I2S_AUDIOFREQ_96K;
  hi2s3.Init.CPOL = I2S_CPOL_LOW;
  hi2s3.Init.ClockSource = I2S_CLOCK_PLL;
  hi2s3.Init.FullDuplexMode = I2S_FULLDUPLEXMODE_DISABLE;
  if (HAL_I2S_Init(&hi2s3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2S3_Init 2 */

  /* USER CODE END I2S3_Init 2 */

}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_2;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 10;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOE_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(CS_I2C_SPI_GPIO_Port, CS_I2C_SPI_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(OTG_FS_PowerSwitchOn_GPIO_Port, OTG_FS_PowerSwitchOn_Pin, GPIO_PIN_SET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOD, LD4_Pin|LD3_Pin|LD5_Pin|LD6_Pin 
                          |Audio_RST_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : CS_I2C_SPI_Pin */
  GPIO_InitStruct.Pin = CS_I2C_SPI_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(CS_I2C_SPI_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : OTG_FS_PowerSwitchOn_Pin */
  GPIO_InitStruct.Pin = OTG_FS_PowerSwitchOn_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(OTG_FS_PowerSwitchOn_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PDM_OUT_Pin */
  GPIO_InitStruct.Pin = PDM_OUT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(PDM_OUT_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PA0 */
  GPIO_InitStruct.Pin = GPIO_PIN_0;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pin : BOOT1_Pin */
  GPIO_InitStruct.Pin = BOOT1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(BOOT1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : CLK_IN_Pin */
  GPIO_InitStruct.Pin = CLK_IN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(CLK_IN_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : LD4_Pin LD3_Pin LD5_Pin LD6_Pin 
                           Audio_RST_Pin */
  GPIO_InitStruct.Pin = LD4_Pin|LD3_Pin|LD5_Pin|LD6_Pin 
                          |Audio_RST_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

  /*Configure GPIO pin : OTG_FS_OverCurrent_Pin */
  GPIO_InitStruct.Pin = OTG_FS_OverCurrent_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(OTG_FS_OverCurrent_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : MEMS_INT2_Pin */
  GPIO_InitStruct.Pin = MEMS_INT2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_EVT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(MEMS_INT2_GPIO_Port, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */

  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{ 
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     tex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
