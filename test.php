<?php
/**
 * Created by PhpStorm.
 * User: hanchangxu
 * Date: 2019/1/28
 * Time: 上午11:33
 */

require_once __DIR__ ."/vendor/autoload.php";
//require __DIR__ . "/ECDH-PHP/autoloader.php";

use Elliptic\EC;

//定义的常量，后面的注释是对英文名字的翻译
const MAGIC_CRYPT_START = 0x01; //加密
const MAGIC_COMPRESS_CRYPT_START = 0x02; //压缩加密
const NEW_MAGIC_CRYPT_START = 0x03; //新加密
const NEW_MAGIC_COMPRESS_CRYPT_START = 0x04; //新压缩加密
const NEW_MAGIC_COMPRESS_CRYPT_START1 = 0x05; //新压缩加密1
const MAGIC_NO_COMPRESS_START1 = 0x06; //不压缩1
const MAGIC_COMPRESS_START2 = 0x07; //压缩2
const MAGIC_NO_COMPRESS_NO_CRYPT_START = 0x08; //不压缩不加密
const MAGIC_COMPRESS_NO_CRYPT_START = 0x09; //压缩不加密

const MAGIC_END = 0x00;

const SERVER_PRI_KEY = '2720858b9c1c4ac93f7ccd1c584dacdd17be778a0e9d21192379f98249dff08d';
const TEA_BLOCK_LEN = 8;

// 读入文件
$filePath = !empty($argv[1])?$argv[1]:'';
if (empty($filePath)) {
    echo 'need file path'.PHP_EOL;
    return;
}

// 获取文件内容和大小
if (!file_exists($filePath)) {
    echo 'no file'.PHP_EOL;
    return;
}

$fileSize = filesize($filePath);

// 获取内容
$fileContent = file_get_contents($filePath);

//根据内容获取path
$startPos = getFileStartPos($fileContent, $fileSize, 2);
if ($startPos == -1) {
    echo 'wrong start pos';
    return;
}

$lastSeq = 0;

$outputContent = "";
$pos = $startPos;
$outputFile = fopen($filePath.'.log', 'wb+');
while (1) {
    $pos = decodeFile($fileContent, $fileSize, $pos, $outputFile);
    if ($pos == -1) {
        break;
    }
}
fclose($outputFile);
echo 'done'.PHP_EOL;


function isGoodBuffer(&$fileContent, $fileSize, $offset, $count) {
    //如果开始就是filesize，直接返回true
    if ($offset == $fileSize) return true;
    $cryptKeyLen = 0; //加密的key的长度
    $headerLen = 0; //header信息的长度
    $char = unpack('C', $fileContent, $offset)[1];
    if (MAGIC_CRYPT_START == $char || MAGIC_COMPRESS_CRYPT_START == $char) {
        //如果是0x01或者0x02的格式，header是1+4
        $headerLen = 1 + 4;
    } else if (NEW_MAGIC_CRYPT_START == $char || NEW_MAGIC_COMPRESS_CRYPT_START == $char
        || NEW_MAGIC_COMPRESS_CRYPT_START1 == $char) {
        $headerLen = 1 + 2 + 1 + 1 + 4;
    } else if (MAGIC_COMPRESS_START2 == $char || MAGIC_NO_COMPRESS_START1 == $char
        || MAGIC_NO_COMPRESS_NO_CRYPT_START == $char || MAGIC_COMPRESS_NO_CRYPT_START == $char) { //目前我们应用的应该是这一种
        $headerLen = 1 + 2 + 1 + 1 + 4 + 64;
        $cryptKeyLen = 64;
    } else {
        // '_buffer[%d]:%d != MAGIC_NUM_START'%(_offset, _buffer[_offset]))
        return false;
    }
    // 如果当前其实位置加上头部信息，加上1位的结束信息，比整个filesize长，说明长度不够，返回false
    if ($offset + $headerLen + 1 + 1 > $fileSize) {
        // 'offset:%d > len(buffer):%d'%(_offset, len(_buffer))
        return false;
    }
    //获取最后的长度, 除却加密字串后的最后四位是长度
    $length = unpack('L', substr($fileContent, $offset + $headerLen - $cryptKeyLen - 4, 4), 0)[1];
    if ($offset + $headerLen + $length + 1 > $fileSize) {
        return false;
    }
    //如果最后结束的画不是
    if (MAGIC_END != $fileContent[$offset + $headerLen + $length]) {
        return false;
    }
    if ($count <= 1) return true;
    return isGoodBuffer($fileContent, $fileSize, $offset + $headerLen + $length + 1, $count - 1);
}

function getFileStartPos(&$fileContent, $fileSize, $count) {
    $offset = 0;
    while (true) {
        if ($offset >= $fileSize) break;
        //如果当前开头的表示在0x01-0x09中(即在范围之内)
        $int = unpack('C', $fileContent, $offset)[1];
        if ($int >= MAGIC_CRYPT_START && $int <= MAGIC_COMPRESS_NO_CRYPT_START) {
            if (isGoodBuffer($fileContent, $fileSize, $offset, $count)) {
                return $offset;
            }
        }
        $offset += 1;
    }
    return $offset;
}

function decodeFile(&$fileContent, $fileSize, $offset, $outputFile) {
    if ($offset >= $fileSize) return -1;
    //校验当前位置是否为一个完成的内容
    if (!isGoodBuffer($fileContent, $fileSize, $offset, 1)) {
        $fixPos = getFileStartPos(substr($fileContent, $offset), $fileSize - $offset, 1);
        if ($fixPos == -1) {
            return -1;
        } else {
            $text = sprintf("[F]decode_log_file.py decode error len=%d\n", $fixPos);
            fwrite($outputFile, $text);
            return $fixPos;
        }
    }
    //初始化, 获取当前是哪种加密的类型
    $cryptKeyLen = 0;
    $headerLen = 0;
    $char = unpack('C', $fileContent, $offset)[1];
    if (MAGIC_CRYPT_START == $char || MAGIC_COMPRESS_CRYPT_START == $char) {
        $headerLen = 1 + 4;
    } else if (NEW_MAGIC_CRYPT_START == $char || NEW_MAGIC_COMPRESS_CRYPT_START == $char ||
        NEW_MAGIC_COMPRESS_CRYPT_START1 == $char) {
        $headerLen = 1 + 2 + 1 + 1 + 4;
    } else if (MAGIC_COMPRESS_START2 == $char || MAGIC_NO_COMPRESS_START1 == $char ||
        MAGIC_NO_COMPRESS_NO_CRYPT_START == $char || MAGIC_COMPRESS_NO_CRYPT_START == $char) {
        $headerLen = 1 + 2 + 1 + 1 + 4 + 64;
        $cryptKeyLen = 64;
    } else {
        $text = sprintf("in DecodeBuffer _buffer[%zu]:%d != MAGIC_NUM_START", $offset, intval($char));
        fwrite($outputFile, $text);
        return -1;
    }
    //获取最后的长度, 除却加密字串后的最后四位是长度
    $length = unpack('L', $fileContent, $offset + $headerLen - $cryptKeyLen - 4)[1];
    //目前只按照ecdh的方法进行解密
    $seq = unpack('S', $fileContent, $offset + $headerLen - $cryptKeyLen - 4 - 2 - 2)[1];
//    $beginHour = unpack('X', $fileContent, $offset + $headerLen - $cryptKeyLen - 4 - 1 - 1);
//    $endHour = unpack('X', $fileContent, $offset + $headerLen - $cryptKeyLen - 4 - 1);
    //判断上一个的序号
    global $lastSeq;
    if ($seq != 0 && $seq != 1 && $lastSeq != 0 && $lastSeq != $seq - 1) {
        $text = sprintf("[F]decode_log_file.py log seq:%d-%d is missing\n", $lastSeq + 1, $seq - 1);
        fwrite($outputFile, $text);
    }
    if ($seq != 0) {
        $lastSeq = $seq;
    }
    $resultOutput = '';
    //对字符串开始进行解密, 仅支持这一种
    if (MAGIC_COMPRESS_START2 == $char) {
        //获取秘钥
        $clientPubKeys = substr($fileContent, $offset + $headerLen - $cryptKeyLen, 64);
        $hexClientPubKeys = unpack('H*', $clientPubKeys);
        $serverPriKey = hex2bin(SERVER_PRI_KEY);
        $ec = new EC('secp256k1');
        $sevPrivateKey = $ec->keyFromPrivate(SERVER_PRI_KEY);
        $clientPubKey = $ec->keyFromPublic([
            'x' => substr(implode('', $hexClientPubKeys), 0, 64),
            'y' => substr(implode('', $hexClientPubKeys), 64, 64),
        ]);
        $shareKey = $sevPrivateKey->derive($clientPubKey->getPublic());
        $teaKey = hex2bin($shareKey->toString($hex = 16));
        $teaKey = unpack('L*', $teaKey);

        $tmp = substr($fileContent, $offset + $headerLen, $length);
        $tmpOutput = teaDecrypt($tmp, $teaKey);
        //进行解压缩
        $params = array('window' => -15);
        stream_filter_append($outputFile, 'zlib.inflate', STREAM_FILTER_WRITE, $params);
        $resultOutput = fwrite($outputFile, $tmpOutput);
    }
    if (empty($resultOutput)) {
        fwrite($outputFile, 'zlib decode false'.PHP_EOL);
    }
    return $offset + $headerLen + $length + 1;
}

function teaDecrypt($value, $teaKey) {
    $num = floor(strlen($value) / 8) * 8;
    $ret = '';
    for ($i = 0; $i < $num; $i+=8) {
        if (strlen(substr($value, $i, 8)) < 8){
            echo substr($value, $i, 8);
            echo  $i;
            exit;
        }
        $x = teaDecipher(substr($value, $i, 8), $teaKey);
        $ret .= $x;
    }
    $ret .= substr($value, $num);
    return $ret;
}

function teaDecipher($value, $k) {
    $op = 0xffffffff;
    $v = unpack('L*', $value);
    $v0 = $v[1];
    $v1 = $v[2];
    $k1 = $k[1];
    $k2 = $k[2];
    $k3 = $k[3];
    $k4 = $k[4];
    $delta = 0x9E3779B9;
    $s = ($delta << 4) & $op;
    for ($i = 0; $i < 16; $i++) {
        $v1 = ($v1 - ((($v0 << 4) + $k3) ^ ($v0 + $s) ^ (($v0 >> 5) + $k4))) & $op;
        $v0 = ($v0 - ((($v1 << 4) + $k1) ^ ($v1 + $s) ^ (($v1 >> 5) + $k2))) & $op;
        $s = ($s - $delta) & $op;
    }
    $ans = pack('LL', $v0, $v1);
    return $ans;
}