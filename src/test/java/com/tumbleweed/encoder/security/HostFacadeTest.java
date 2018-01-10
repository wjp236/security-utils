package com.tumbleweed.encoder.security;

import com.tumbleweed.encoder.security.facade.HostFacade;
import org.junit.Test;

import java.util.Map;

/**
 * 描述: Host
 *
 * @author: mylover
 * @Time: 21/12/2017.
 */
public class HostFacadeTest {

    //Pos公钥
    private static String pkPos = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRi7CdW3UaI0pUfrwbClXOFKzsHuJKhNcYJM9R\n" +
            "sp9IpMZ+d+dXw5NZMpHTQtAvSE1G1pSdqEUcvDtPrw2I7SKL51NzMafcVJACZG4acuQJpvbHV+rm\n" +
            "+ymfkkk6/PN5scfXdUubcbYNztx60zqCEbxkse9wis6JkGReouwpaIXNjwIDAQAB";

    //服务端私钥
    private static String skHost = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJyuWY7zrkFmx3R2uGsQtHYpDfhs\n" +
            "vcmX2rNjlLvxWF/xwLfIno/42wZNGnoMXHcf6rSLoP/0OOIamcZMkyCMf4yNoEp6nxub7TY7Sw2X\n" +
            "GS6XN6a+zAraUE5zpQPS4EdnmIr194DP4+8wgQ0UGqO67CTPDFHnoBUd6Wpo/7Ryr74RAgMBAAEC\n" +
            "gYAjy0Dyg4D/t/dBCA5Bh2NyyxZB9rW05Fg2Oz2zYgOKh7Q7SD3RLkz7N4og78n//O6lqHBziNul\n" +
            "6+XNg5jpCq/olMBWozNeirBKXW2LcMP9x3pNXTTZZAjzZ+/dSPBtqarIiyXaqFbBLg1JO/4vRPRB\n" +
            "mpjAGGOKtCNwxHCafSSoAQJBAMhLbtYN1v1UI95hnMnqSVsrwG1OS6WJwSiF1ztFx5AUBUKE3aOk\n" +
            "YQAh8f+NDVXdVwuhyf3O4C98YS1hKn3iV6ECQQDIQbfP5Sh5aVCBBo/QIkRy1DZZHQ+w8I48XG9D\n" +
            "T/k0u0SxfeQ/K1pmkOi4XhDnW24ZanwhSo3H857hucc1LRBxAkALx1PXRq0T7LTHSRo9TYfO0r3Y\n" +
            "L7iHHZi8V1KW672WnXbJuKKIEwyZQ2XFz3evSvrpdjQ4tse8QyY70vD6wirBAkAo7uX3pMvFJXXD\n" +
            "Kegzjw2WuzHwvTP74u/v/qTviWVTFgRQk38YOnBcDrrDFNc3s0SqBU4iL+8TNAUB9st1XyTBAkA7\n" +
            "Ut3kaOK0RuEMz2ZF9UIyg7XgqOXW3cnQsKj/2Y4Pgkwsta6B6t9zz+N5i3x4NAeaF7iVvAeAGkNQ\n" +
            "FKZaE60h";

    /**
     * 验证签名
     */
    @Test
    public void checkSign() throws Exception {
        String sign = "baiCSp9mwbAZVxTwenUvVAs0gb0Xe0kkXzDqEhYAeuGyoLp//b7qWNfZLjgR4k1qFwXQwengSvI4\n" +
                "LtjKTbPexDY4pCLRef0T6xys8+XSY1vNsiOEhvAu2jC+Rf9FMxrnEb5jg1DJqS7EC+nRjZ3ZP9zY\n" +
                "hmJQFyNLrQ9gQQs1cAE=";
        String data = "8CB067EE8FE214BA24776C90334C0923638D244FC03BA9C1093465159A463C7C76A023D5F17BBBB971409573E471B5011C34A17B954F3CA03A4C5325A25197BD071B5E4A774E1F5E030789E4D5573AAEBED98103107D7E550210312C261B36899C461D1AB91703073448CF3F5801BD230D27FA480DCFBD876F24D5501B953324";
        HostFacade.checkSign(pkPos, sign, data);
    }

    /**
     * 响应pos
     */
    @Test
    public void reqPos() throws Exception {
        String rndPosStr = "14664072";
        Map<String, Object> ret = HostFacade.reqPos(skHost, pkPos, rndPosStr);
        System.out.println("Host随机数rndHost:" + ret.get("rndHost"));
        System.out.println("过程密钥:" + ret.get("keyStr"));
        System.out.println("加密后过程密钥:" + ret.get("key"));
        System.out.println("签名sign:" + ret.get("sign"));
        System.out.println("编码后data:" + ret.get("data"));
        System.out.println("ssc:" + ret.get("ssc"));
    }


    /**
     * mac计算
     */
    @Test
    public void mac() throws Exception {

        long ssc = 49435396;
        String key = "fLJ3WkfN";
        String data = "746869734973426F6479313233343536";

        Map<String,Object> ret = HostFacade.mac(data, key, ssc);
        System.out.println("mac:" + ret.get("mac"));
        System.out.println("body:" + ret.get("body"));
    }


}
