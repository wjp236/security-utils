package com.tumbleweed.encoder.security;

import com.tumbleweed.encoder.security.facade.PosFacade;
import org.junit.Test;

import java.util.Map;

/**
 * 描述:pos
 *
 * @author: mylover
 * @Time: 21/12/2017.
 */
public class PosFacadeTest {

    private String body = "thisIsBody123456";

    //服务端公钥
    private static String pkHost = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcrlmO865BZsd0drhrELR2KQ34bL3Jl9qzY5S7\n" +
            "8Vhf8cC3yJ6P+NsGTRp6DFx3H+q0i6D/9DjiGpnGTJMgjH+MjaBKep8bm+02O0sNlxkulzemvswK\n" +
            "2lBOc6UD0uBHZ5iK9feAz+PvMIENFBqjuuwkzwxR56AVHelqaP+0cq++EQIDAQAB";

    //Pos端私钥
    private static String skPos = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJGLsJ1bdRojSlR+vBsKVc4UrOwe\n" +
            "4kqE1xgkz1Gyn0ikxn5351fDk1kykdNC0C9ITUbWlJ2oRRy8O0+vDYjtIovnU3Mxp9xUkAJkbhpy\n" +
            "5Amm9sdX6ub7KZ+SSTr883mxx9d1S5txtg3O3HrTOoIRvGSx73CKzomQZF6i7Clohc2PAgMBAAEC\n" +
            "gYAJDwe0E5ArS00CC01L5Y3HoNPOcnGlL7VvhEL/E74EOHU+Q9o7RSnzoEkhPARXHQnqQcrIMUPz\n" +
            "8OdEI2IVRqUitfQJ0rXZtzYODXsn1m7M5HY4vJwPc0tyW5RI1OlAZHlIaZGGpPBlDIS8L3dH1cjk\n" +
            "8kMvJSRlyvOLeVtWlJ2AOQJBAM3qw7n8wsohwfQAr9R9MNe0K2nHZ4fZMZMo9hhQXp+i9C2KRj7J\n" +
            "dFTfqEJOysKVb1j7Q0eHQ7GQPFF+RN1RiWMCQQC08fTldPk3GWILjukbYW3Za5RItvsxG7uRIR85\n" +
            "e+yVJUWCgL0p8m/fK8kzwUVlEpP/AoX8UzOV0ShZaWC/6vjlAkAYwxeAYSXnesHBHugGDHv4JIFn\n" +
            "+gO4MWUlxjI54EhQuB7W7x7dZApqPm8UcjctyRyXvbdsfZalXqvyPNX5K1nzAkEAir5slfUXkxQ3\n" +
            "hb1TKNeQL4K59Pe5rHIjZKkNFDrdsY8euW6VnbBz75/Xa4Pq/hE8wfDhZBU4HMyAL+8JbJ9zsQJB\n" +
            "AMDXp9mzKj2UIuXSbkC/7VKlcP6jiUU3Z9Te5W9zxVyEzz9VNhDoI8k01P6j4G1RVN9acODHxNM6\n" +
            "c4mo+bc8lh0=";

    /**
     * 签到
     * @throws Exception
     */
    @Test
    public void sign() throws Exception {
        String prefix = "01h";
        String sn = "SN000001";
        String rfu = "id_sdk_000001";

        Map<String, Object> ret =  PosFacade.sign(skPos, prefix, sn, rfu);
        System.out.println("签名sign:" + ret.get("sign"));
        System.out.println("Pos随机数rndPos:" + ret.get("rndPos"));
        System.out.println("sn编号:" + ret.get("sn"));
        System.out.println("rfu:" + ret.get("rfu"));
        System.out.println("编码后data:" + ret.get("data"));
    }

    /**
     * 验证签名
     * @throws Exception
     */
    @Test
    public void checkSign() throws Exception {
        String sign = "XNQFXgp6co4LlWh5uFRNUuejssW544pzRzSu21/6A6/jkcFeoJA8gtg2I8GB93WxAwxdRIgNvgZg\n" +
                "IyONkSn1bAYF8fIFFLcCjUPm3OJuT/b0y6G8Fhs407Es9sKjHDm5yCwRWRr2g1XvwpqEEqlOmPfa\n" +
                "YHtus/ZMtntyK/rrkW4=";
        String data = "9244C5E0F29B7D2AEA91EC6A627672CCD99CA4D6A7454000ADDE0BA51DA0C821AEC76042CB420593D5846715C6B08908B5F24AB2FC8ADD6739C3CE2B283CC975398C84C5DDCD138615ABF22D13E3AB55872C730913316057074B30D14F9F9038E3BCF0BB1C9D48C967D17C51717A358C140D90365B3E7547A345F756568C51CE";
        PosFacade.checkSign(pkHost, sign, data);
    }

    /**
     * 解密过程密钥，获取会话因子
     * @throws Exception
     */
    @Test
    public void makeKey() throws Exception {
        String rndPosStr = "14664072";
        String rndHostStr = "36541068";
        String key = "I8ye0JpQQZKcIHBEwOgzI4vZGbruwd9G2JJpLEQYpVshqmSIQ4xOPMuSWbg4pOr7JjHm09HI2zT1We0IyHqb/fwXiczuOaMqFVljJ5wO3PLrRGs55S6SzWWD7Ta/FJgILwySqBBwWpgrNOoQJB9uD5mCDEAq+i5OuSMyziX/i9w=";

        Map<String, Object> ret = PosFacade.makeKey(skPos, key, rndHostStr, rndPosStr);
        System.out.println("过程密钥key:" + ret.get("key"));
        System.out.println("ssc:" + ret.get("ssc"));
    }

    /**
     * mac计算
     */
    @Test
    public void mac() throws Exception {
        long ssc = 49435396;
        String key = "fLJ3WkfN";
        Map<String,Object> ret = PosFacade.mac(body, key, ssc);
        System.out.println("mac:" + ret.get("mac"));
        System.out.println("data:" + ret.get("data"));
    }

}
