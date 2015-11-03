package trabe.tests;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.util.encoders.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

import trabe.*;
import trabe.lw14.*;

public class Lw14Test {

    private static SecureRandom random;
    private static final AbePublicKey PUBLIC_KEY;

    static {
        AbePublicKey pub = null;
        try {
            // Base64 encoded AbePublicKey from version 1.0.5
            pub = AbePublicKey.readFromByteArray(Base64.decode("AAABZ3R5cGUgYQpxIDg3ODA3MTA3OTk" +
                    "2NjMzMTI1MjI0Mzc3ODE5ODQ3NTQwNDk4MTU4MDY4ODMxOTk0MTQyMDgyMTEwMjg2NTMzOTkyN" +
                    "jY0NzU2MzA4ODAyMjI5NTcwNzg2MjUxNzk0MjI2NjIyMjE0MjMxNTU4NTg3Njk1ODIzMTc0NTk" +
                    "yNzc3MTMzNjczMTc0ODEzMjQ5MjUxMjk5OTgyMjQ3OTEKaCAxMjAxNjAxMjI2NDg5MTE0NjA3O" +
                    "TM4ODgyMTM2Njc0MDUzNDIwNDgwMjk1NDQwMTI1MTMxMTgyMjkxOTYxNTEzMTA0NzIwNzI4OTM" +
                    "1OTcwNDUzMTEwMjg0NDgwMjE4MzkwNjUzNzc4Njc3NgpyIDczMDc1MDgxODY2NTQ1MTYyMTM2M" +
                    "TExOTI0NTU3MTUwNDkwMTQwNTk3NjU1OTYxNwpleHAyIDE1OQpleHAxIDEwNwpzaWduMSAxCnN" +
                    "pZ24wIDEKAAAACwAAAAABAAAAgA2lA9jJ0PYurbFMFkIc6UXTBpu7celGgdx5JAMlvML6cITxH" +
                    "G8U96uf5bUEmgrtYo/F2BEuywShDIU7N4SGP/GO2qzvaufgAILZ7Z74JXs6VZBvApC4jg8Srqw" +
                    "otupyDaf0DiTOjAhbHw8e43LqszsiMIDGGtsDpxNt/JP/Xff5AAAAAAABAAAAgIfau11JuoHAm" +
                    "vVZAJ8RClXz7vNPOBgVCp2x2Dl8Q+WIvotz1AuDQzcb7LwFQHLnz6WgEF8lysSX95O/vWlSj+2" +
                    "SRcTZLYokwaGERkQTWqww9om0KtWbpNeT81Fu8kxGLWcdmsYY1pcCudiMPWmyLvjGoLcJ0WD8A" +
                    "+Ya7YyjZRC1AAAAAAABAAAAgC/f6e3yPlOV/cImNqZ4t7y1xPg6Rh+mBYPvqvVH/gAeYjxIlHk" +
                    "M0K3YKm0RxDU3G1IKbDOwixBAIt87ixYvElNOnaPCz4bKh3FW6bcI0gyy7vCwvb21k59g6BcfZ" +
                    "3hS75Qh/0UnUw1ItyKdnirEnBfIaPMeoDsNn1wJ7Hqe40SyAAAAAAABAAAAgGNU1MX5ZNdVdTp" +
                    "pRBQLCLE1kCPW3H0hTIE86X/Q7tXC3bpl3p0LHeP1ur1706rPPZbHkpERPDRTAwYI+OlsLiF2M" +
                    "FnblMNvQP7OFGuc6Ub9Ft+QxKDhwZAELjVNS5fRfML2ut7YFPULTsm/gCflJdNHvGEsO3mquto" +
                    "N7NU0neTdAAAAAAABAAAAgHYN8diKW/VNuHrwnT8CIz/DO596hZX3BSJPFwRg8w8WJWxnYeh6K" +
                    "cfVoO6JG8AFJl/XuXTpoMK+vzxqb4WGLele6+TnN9VajbhPWrAh2IWlzvfyb3eHFbNSM1L7wiG" +
                    "DriNXFvZLOtiUIdhHsVoQ/xOU/IFAaDQhpFLWFWgw9w8xAAAAAAABAAAAgIJC4X3A2ly/+vMJR" +
                    "/9LHTPV8iOgso9FG7oKdpKDkppR8VALEZ/Ylp41Z/0JS+x2+ndf4M0aZ5iVohhzPj/VpGsdV6u" +
                    "QbeA1VCw8+Dx8+IQnsl7zwLOTV0jtOnkr69HFE9VLe50wrrkZUasnv1fkc9E0Snps6Xp5S/yt1" +
                    "30DDLCAAAAAAAABAAAAgBvU3EUaX6swt/Hd+9q9e5loRFT9vy2NW1kXN0lfD8xZFjwE1BYuRKO" +
                    "GFV+iAMo2sXRIYIu0c2dNsnx5FPoKOwtTajV/Z+HxzbDO+BgnVzJgLYF+YpFhj33djgbykkJkv" +
                    "dN7I3V09YdIIn3C9releweFUJ/ZvLJFm2aCjZFVhqRmAAAAAAABAAAAgG0CU3TqRJpW7MwTjNo" +
                    "ftjiIcTuDiFYm/7+59V33Zc2/z0apke93ndcnrK/AF8aN5Bvbm9YmrkMg9EOwJEb1soFWb+iKM" +
                    "+y9+jClwhmg9pcAX+CElN21ySZk6cf7MLsp8SJ8kzcT5LMmmm5Viic+NzW5vOGabD4rdc6o5/k" +
                    "qBsHRAAAAAAABAAAAgCWO0y4u4uLGA85sVHoYoly4UTt3qK+Mwu+HL0JfFkr3OnxdyV2xtD6kb" +
                    "wTSX9bYFvY8dP1ud2WlT3W6qfaX6EEtgGF2D8kdGbZ4cRyTIeg2hqqPZ98CF/U4pGOIV88FIi0" +
                    "lj3NNGt7TCj2eXbYS+1wtnnf9ckZLLwcgT0NeBLBaAAAAAAABAAAAgGawj0k2voPwXkt5cD+CZ" +
                    "kOp/YFjzXMZKeq9BSnwNvgvBUZPYe7cwjUoXtu1Oa2wAvdrgMyJ5kFTMXp82SFG94xLPA0hw6h" +
                    "Y6ELHMQitvD8jHE9lOffy2CKOGOlsDneDimg1Huazw8IvEsVObvycv+68hWOxNAN7oFjlzhVGW" +
                    "jOmAAAAAAABAAAAgIHUyf1sq727pAKremTIKPR4bLMRVK8xmoh6rlz862kGlQczx3HnKgFfrhv" +
                    "oKaGDa0a8SgvtzvHR8PTwywwiEPEGlCgo2cF/IzzWJnM7fStB/VjFKxab4nANq1t/7kYMtsNo7" +
                    "994KOV/SYVgIRqnDiMvvd54DD1JxTa2CwCqVv7qAAAAAAABAAAAgIBpUbe/YA0jt89oXmNcG6R" +
                    "/5sywoC4yIg1bBO9SHGfhje3FFupVQKM7HEmphkO6fn0cfUIYr+qfrsBMaZOg6bmCtFnum7bZH" +
                    "MVmJegK5Rv3cG0bfY/0UeueM8rTw7RidNFABGI25zvNNW5L7pS3FfTcIfIbH1FJsNC+kgLILLV" +
                    "zAAAAAAABAAAAgAB4nLJjUxg5QWGEuHE7SVC3obeGb9/tARjsHDnqcNUzk6Mg+zYJ8KQ6i9396" +
                    "jzXfgIJZU+tHC9UN/SCzOQb99hqg92QoufNOEd0gyUP2bXFovUSd9AaVqXS2K21PDqDcb1EiXo" +
                    "LinokOoPi/juOn7RkPF2VK4xSrdhAsMZABAqfAAAAAAABAAAAgC2+0qysaij7/MsgsbR5IjaqJ" +
                    "ZgTBPb97XRv7uq15563/gNmPfCTEGnosYmswAMBkoVTtNLJtknqhFpC+e6Wko8UtxFW4kcoCpu" +
                    "85U6G2QERpbHwEmI0yX2LMPQbtMK09cyfwNEP4Uyg4jJTXzcqAPm9rodLe5i3CJzJBWpjH9grA" +
                    "AAAAAABAAAAgJLPNq2fzPvpBj0iLZW3c9aNTtKICPK7yb+aBdFsVDCSkmgv5UdrMqTw8YnTS9w" +
                    "kBOagNQM2jLnTIA67gv6sF4oy886f7PpYXTcSewHLmYGj+lA5obM8CQl7uYnzvpCK0JqLUE2ur" +
                    "2PKZS5KTbqvNFksgtej/n4mostdIUBLyw6CAAAAAAABAAAAgG8YrX8s4sWMpj4mYZHH6b93g8t" +
                    "nw1CKISnzn+HNOswQh8VBdJfHno8+tOv+ZttryeLbBjW+6+8f01iiMt0EoY2Uk/G3uQWG7sjFe" +
                    "nUlulLCgI2RSEEbjoyX+5XKdJNE31KzArpnAdaNu63R25796viZb9KNqtY4vH98a6CNRE1aAAA" +
                    "AAAADAAAAgB1hCtkpeSJDNB4KJ6jD2V9h0rl2RTTL2gLihQyPMg41wTCMuoQxd7hX0MjqIpqmS" +
                    "CFugy1ODXtYCgBa55DKTRUzBzis6PdV+nEBRP4gx8Uwi20dqO6fRHzrd1JBspXlOUCB72mcevq" +
                    "ZkCLf/Q8NkaQEod+5AkqGB6bMSI3xT5kPAAAAAAADAAAAgD+pplhvr6Mdi2CQ2346/F1HpksQY" +
                    "QuQdVdhacaWL+bqkfjis0aOyHgID3hBJWT3ELO7XyjxP6KpbLqcUKmfpcAvvmrxaHhu0CF16uU" +
                    "O3GGlDsc4iL98gQYWBir9jc+BBHEB6ofxkJ8o+HpOqIAu9j17fhXhdkk6XrxHZwAHqrAjAAAAA" +
                    "AADAAAAgHR6dmbWEfbXhK2jU99HKw3UQEBeC4f+zx88eDkGni/XHbjJFGkmliLojmDLmGJOyyQ" +
                    "yRSMVBd4R/scUdZIJM4lQSlFePmDVkz5el29WIDWXUg6mJpCglRVfhVrUoRgVjWeF/ezOLVEHZ" +
                    "RnkGWOgCmXxshnTds3fP/GN7B3LzHOOAAAAAAADAAAAgGshziXn1CtG6J3kn3IwDM/KY0DV2nE" +
                    "kL3h75EdVW2VkfarEOkCdZYEpAIdLeybx3DzDXxWbT1HSlW0M/5goT48fpqzt8bIHzoFgpviFd" +
                    "OjJ0Xl+01L2u5QJneP8fMjkUyFAgLlNMpqP/JslQvVNuW0m3F0dwGv8IF6+sdnyjB8ZAAAAAAA" +
                    "DAAAAgHdjxKzOrkjjce9P2boyixGOt2YRNg1j+sRGQ5JAIgehA7FqMsyRSYDLEkx2cUyR1K2nP" +
                    "QYu8WowT7N7xR6LCbiFVY7uYGvGtIWrS3JaOZbwerICNNTICcsr4pJdGe0WY8FKlIcCMGqmEou" +
                    "5JY/klHX1qk+YtzYlRwVT1HbbktaDAAAAAAADAAAAgAiQNU24WdRjGJyBIl8heT4wPZ4Mhhnvh" +
                    "J0iY3QDJGSaxhD1m7yXHgaWLe3vNEvzCb8kzKSWbU3hAwO3co9F1yZ3WfSEjIScpgmeNjcBxRZ" +
                    "POlK3DKNHd1u9aR+k6BeB3DZTdBLvUtAOOOuRTVrRMcsaZLE/ribNeAJsrN6zsV5cAAAAAAADA" +
                    "AAAgAN/DjNuz7p8x8EDyyiJKePEjVCizFr+BcbLI/8AmmbWvxCldeQkLEVtCAXFfgULZML+Oue" +
                    "07a92A3vYmsXVHE4sY18oKZJY4eOL/NRmUY81IWMJkx2M7ZwzDYhx9W1ZOdz8jS4aUaksvjbY4" +
                    "EmKLmpZWUDJMMW8vGhor4Kar4W2AAAAAAADAAAAgJRhNxB+YN8h+qlefrK9enlHf7IEplFqz7b" +
                    "pleP42lVMOPRJjwJA/ZTMcbRylEWD3Yxvw0Rcqd0O8Qki62KNGvowEi2+ChH7ha/x3WyrpNeZk" +
                    "vBj0UuGFL+L/g2Kqf49JGOFoBHzxjeMnl+zJZn8XGwBlIyLc/Xy0mY4m6u/aqHKAAAAAAADAAA" +
                    "AgA5F5cYfWkzBxL5HV4PK0OJAF56VBI2CEuFTUAFEfn1YxXp0tlHYkCtT5ogm+ryo0L6w1MeOy" +
                    "bWCtr0O4/XHC2R8JIR9YnmbSYSR9vMxPcwz5/B6I9z7DEt1g92IPcZoSjpXwLCXEzCkWggqARL" +
                    "FgRKdnQ6//cW25wboqMor9iDiAAAAAAADAAAAgE/j/TJnxa/vh76yovc5TEC9Cn5e1ANAMXJmC" +
                    "Wxf77AX0nlVH8zia7f2ojwVLLSdI4eg/vQPU9qVoup42FNTS3um81eciaQL137XuPQxYlHYSDE" +
                    "+P1Tn1B3HxZMev0ZUZ86gy4wJrNjNCLKSoPEGdIffWmAmYJN2z5LsQVBqRu1nAAAAAAADAAAAg" +
                    "JmNHHnglG3ixwx4NUtGWPtCUDnDQc+RGEcPfO4YvkmYO08b/D06Qm6jzRZn605eWTSrhjvh14P" +
                    "LtA6O9Aa4aHhh2xxLX1FhoGDC/iPByz3iVPYL5t0+uQSa7X4wm44g92FnC+o0r5o2IlFUNeCTM" +
                    "lp2w+CNyC4zjrxVaTpWJtPoAAAAAAABAAAAgI8QynPoixHH+WOnr8eVjD9fSNExV6IzG5zaZON" +
                    "nTRIb2f/lyeT+RILKW81VmWn0s2UG4EFjqT3C6rSAMz+s76QWi/NDBaEZKiLnEu00/01Cr1Z87" +
                    "lo26E86E+qXHQFyR8aFcNBPXgvfX+x7nNnXM8aCOwEDAgtKzqOmHbFkLnE3AAAAAAABAAAAgI6" +
                    "ikDywKld576VJYi3dqNOiBX/kOq2JOCBkqXCKVNI8aDaIc56lr6KGB9wj8QR/HI/2oyzJDr4NP" +
                    "LEOlRQAHwkZJSNOAMnbAjaODQa7b5V0z1M3Luzh+ABUDXhFYY2THDm/EpscEhVeCzVZZsspqwu" +
                    "mOB+v63FMwKsAlbmFge1bAAAAAAABAAAAgG0C7DkyTlofKqzcitS2dPibjP2tH3TPuoh3EK1I4" +
                    "VMaWRvJ0nYXW/DyQL1uqKmDhLQKEaSSl34fndKMFA7aK1gs9Z9BcXr5VAzi4TcWCyw71mEUM70" +
                    "/s9CjOndoGZbTmz/1fdCxlhWtxi0oz5sZ5rdgi99VdU7U0E8l1rQRH/ozAAAAAAABAAAAgADDT" +
                    "4BvqmKBoXyU+rTSeRt9kFtc5a8Tvr6P3hHxL+im6PK1QJESQ74tft7qfao0v+DEt0PmMubJhPI" +
                    "tvJfqngt/SpHWhGMbNUdDLWF+3HoaqigF1qf5yvWE4M+en7Pqxbz/ng3l40wRYEN0B6wzJWmt+" +
                    "o/M2lDH155G0H2uVDjoAAAAAAABAAAAgGPjtEAZbxdvjAZONarUnmj2e5mSHJKyT/04h2ndDgU" +
                    "8z5FBBKHR6hz6FGsXOOUHJyaAynwsyU4hPZz0EO3Qq+otc9IVOhfBGqjx8Z5L3LbmpgaQVOgdE" +
                    "tk4BNl+prcLLxsuMPhVzFkACtC+NLMbXE85qkJb8+ha0zEd8DzS5hYQAAAAAAABAAAAgD4Kgjp" +
                    "COcRZuOznzCFAZ01rYtgjR9A5M7irhZ8B5VD+Bg1RAmNMm+vWCW9I+HJqjBCAcsAkKgN5PIv1Q" +
                    "Eao+00gLWYGUoIgWhUNuOL673wTVIRgSGBYuvObKeS/4UIP/AdQvC/lIEfsc0UmAXyMZR8hGZb" +
                    "WZoe81p3tpUCo5BvvAAAAAAABAAAAgANYbjLVSkoPWuEGLC3vmIPPC98/OPRJdU1fzXOdXE46W" +
                    "Oek3yOHMlo55O+A/ikMa7SWpycY09HVqYOnSYORrcdhxJosUcXs5uDYNG25i4lfmzfl+P6g3Ni" +
                    "QumscdWGd1avXFTMww9ckqacYyLck1fGoKYZvxo1sgUE+1istPpLkAAAAAAABAAAAgAMV0PIN9" +
                    "U27+s4E2/l0qWunToaPEFA5HTcQG8iFID9fSSk6qCaWQkXGPD7hlx1eBnzDWHVxMdyUS5tWIoG" +
                    "KAS9lF37lNB9XnzIvqrTukCoOqQOxm9zlGagVRLiB1PoXxEAb6A41Eezg7hV1vO7hkwnTu6ABQ" +
                    "ypIaSBecNOshXWFAAAAAAABAAAAgEadO9V77lxuK380nnx7N3TnhvBpJ8GAK5tLq99OLTqc159" +
                    "hNhucsn2y0buac9KPt5JoXi8aW84AXedmrvE7iTFmNsYpbCyBsxzLBqD9AZ+bkrU9I2dlueFPg" +
                    "+traY6PG0FiPuO/psGu0JLUUbWuHxHbjaOct+t0PdBbjm9sFloeAAAAAAABAAAAgBw6Hp6jucn" +
                    "JbBZVFhaQ8i1w+Art4JQH4Yqnn8blcDJZcnqqC8smNhh0xChWPf+AGlLXT5oCaw0ERA9rVV6YT" +
                    "immPENOWJfHXwsJL4RhGYSAGD+M1tMS/jWNIRqgVaAlBtvBmhu5DG2w0KMtd6Agsqfy+LJciRG" +
                    "YdKJDuqT0ox5EAAAAAAABAAAAgJIhW/g7Mbqj5IdApJlJur2n1evwbe24HvZn10Q/cy9yXr2MD" +
                    "9NIvG5RFy+YW5VGvMl8NZRTJWTtjBKW5U3neUik4etVU8H2IyxlZK2urNZ+Xiq9u/qxgB+QYM9" +
                    "FFnI6AZdr5fh9JoeeJf1tb1E/3I2B418lpuXWE5Jw1mfiy2LSAAAAAAABAAAAgAr403aVnx8aR" +
                    "X5EOxvLvz3wYXXvbLzMubc4h2sjJSyjx6/ANBzgP2oT4Zsus6+4AB7NWULpFyZPGJUAhwVJ5GE" +
                    "6lNymkipg7ei4ldhnavhfFjHCdzg9BQImkVtm00Uj7vucUm5Lmsf0rsqu02hM/KJEqib1B/Kcb" +
                    "dktJPcu8C6fAAAAAAABAAAAgEALe52XibC75FwqbKFgAy9wa8KQqQX9SUqaBc+woGGvtJGLdU8" +
                    "yE+HQY+CtTiJZAUckfvAZdA/jCTxXTizodd8SEz6Cnt835TL8AhGYqg6UeLF/cI6QVBw9CQF/H" +
                    "8CWj2P/jAES75FoZJVW/MhAd5rqLrWzOGyTS97zpXKfvOeRAAAAAAABAAAAgJm1SejeLXDOrxf" +
                    "teVnH2PvmdAfsQFei95zkzPRPbQTGA1xnQJ4d0ovyWKR7S8QvhEkbWQrSeWgNCkvK+LbLMmpwC" +
                    "VLtzOx5LogMkxUhawqCwQTw83guA5Fg3P4rbkTX3+cTgF/pkhCRe8hCcW+WMYCZPL8K/nu0Dtp" +
                    "o727QawvsAAAAAAABAAAAgExp4u9OcPzjAMy0ITh+xJGxQLFfbQFuSH8CsO3QfJi9e+ffKtPGp" +
                    "Rj9Q6Z9CI0DzjRwGuFjs2BiwwT4JgXsTBqGHCbEBnEBP40m4us7kj44jGDZgRn1C0+LKsFqCWj" +
                    "PSiLLhNnKhgnPvk084iegsWztgr3hxPAGe26qlgRrEoY5AAAAAAABAAAAgFKsoTLlzJjX2kwzq" +
                    "BsRqbtsCFatlwlUwPVP563lkPredyNMJOCMa1eUERLZ9EaT4UJeV1zAg6B1NfPOrzz+qAsO5pj" +
                    "IvBbIZ5b04INaN6x8SL1AFkLXUg0FiOox0ZvzmHQBt4QUcRUYfvtX9KluEgOXv+V4sVlOsw6KN" +
                    "uf87Y2nAAAAAAABAAAAgEU4HpAJtsZNIZAuvQ/Zy/EdR3zX7KRtQWa4yafFPtwnCBZsqrY6TG9" +
                    "jT1zCPYe3j1nVDgbwO4jJUkUfgb2fbZsjys/WvK3PiDWFITIRS2VSmplKBOv+wydVY1KP3uOgY" +
                    "yEzwjhW0X2/YvvphTPvDVScNf7v0bXide4lesRCJ4K9AAAAAAABAAAAgEMX1gFWG4+2N+GUZVK" +
                    "Wth0pwPLP0MEQJBXCPK6sqLzAp+JfBa7BmFR+hNvMUkoFgk1bnlwr14HmKTpVzKvh138XCOG5g" +
                    "XKesoRWdo0CIVzRXKnVVtme/aLY70D+Efbsn7Ahul8xhgdPsVf64pRU6s8RktMXU5Xt4hUbIer" +
                    "XazQrAAAAAAABAAAAgH5QOg6kLYeWmQgZ6gsU5LOEkH404JHKLhtzRzaDb/6TlXuDCrW0HwXXU" +
                    "dyzPFsbhgwOc+aE5msJPUI6+RiIXP6MdNzSPyGdor7Y9XRf4zPchDsSRgS7my+Zz/MTXGjP0S9" +
                    "0S5z9FTrcu+iu5x5IwjnZnounuqL8NCLN9+AzRUOpAAAAAAABAAAAgFzzyUgYcgl0jRDKEdu4q" +
                    "5czj2iY26jJJNMrNTxseN3oYk21eD8w0/p1X3xs8cUJmaX141302Ur/0s1ndv3csdZ8VR1RH03" +
                    "IOl963yvKpk2UNYzCpCDBjyGpyQvSXDQh3+/ip4HsUWcj4YY5HW1xKzFps1Ub4Ws1E0+v2LWp1" +
                    "bUhAAAAAAABAAAAgHTpNwhLkY8G6KVA0GesMBN+rYz121ENWbzwdEpI7aT+TwELRL7/LBxA4Sk" +
                    "LARJsS/vZ3X+oUZbJQFnPnUizo9ofMe5bhyrJFONvwLXIdEuTOpkZ71V7mDiODJTSAaYIlS+20" +
                    "+7mtGQ9Ob/5psrHYgVXSX3sh16I+YFkmTUeZ3IcAAAAAAABAAAAgD9QqIwD2OSoxNkAEhV0e2Q" +
                    "pHzl8t5+2Cm7GWI6fE+n1gFgV9T59kRK20Rmeap1esh1IXO7BPdU42hv7rrWq10IGJKGq4zfcY" +
                    "xFID6ePFxBtCat/3r4yZ3ADBEsFyVvMUhsYIj1YrRjhi9z+l1Ppj0gxVFdlpQU/0Bfy/mLYgvI" +
                    "lAAAAAAABAAAAgDIaQDkm6S9GpmLuEwpR1w62b32Pa3rpXKnhNtK2G/daIhftlhYk95uyTjkug" +
                    "nv/fiVV5MbSHsrOPXN26V4jS9BHrQR2d4Lp26TfpZoWmP9+UsyOZvhIQKKapInksja0Xow2w6l" +
                    "eFztRGRFH+N6GVK6r2MMFnvpOpffaMXFdywSQAAAAAAABAAAAgKRTqtaxmp7viHmOHbgBjOj4g" +
                    "9xHTdJBUr+JulVM1Y9R+JABOWEvoAkW2ujt5HL+Xi4HAOjLmCyh+C5YC1VWQwClvbbYbac73xA" +
                    "a0wGH1gv5FA053XMEv8zhpfPFRyfvCWaj0HJTGrvblHMokXfcQB0WM8pOVY0ORPSu+QulIxO0A" +
                    "AAAAAABAAAAgA6B0y08+IVsE+m1pU2tz/4Sk7S+tO3pCK8KWp0h1vh2q3J89PiRVimbqFMFgZ8" +
                    "FGEyNC8tEe7kIbJc77ybuK3NW2/Ht9w4fs6TPIjL+ps6uFfcjUfAovCeCbON62CKs0sabV/WkT" +
                    "EGmy7OFB6x5OFfZzaFGZXRZqOo8Xg/ReOw9AAAAAAABAAAAgDHS0+xYOI5IP24SEUSjl4cvfDR" +
                    "9T2rijm+7KG/REDFX3gwSp1zkfXHvsaW2o/m4961CglgZrh4asiLHpEaMSUYYL9b02R9bk1irW" +
                    "EyI20sH3w7txXchQYpMj+yPlWS3MQ2AYE1jjWLCLE5SDLi6Vr4I1tVgiwZNwx61nqUedofrAAA" +
                    "AAAABAAAAgGKpjd1QlWSQSzVyNmP3AW57i61eKTJkcZr6K6AxURlT5GfEc15IxUE2hIoSzQ+h/" +
                    "nSguir3kypBuaWJSW064k1WOK6DU7shsG6i/br/IFe/BMIV1gJE/2ycurBkDWGuDLfIwoKgGZR" +
                    "In7930mkMmGCGNWrRThWM8h5PgLqGyq6tAAAAAAABAAAAgCmkxtcCNGGugGuw1iirHY1o9ryIQ" +
                    "W5beA3AuPfsf/gq8s1WjgSDw/NuPhGOC++nF+nX7x3KcLUstxk1je0hbE9y/fw5VkgUMBNuPzR" +
                    "R2/Oh6xHum5LQsdzD4n5OKw1o5voPiEfwiWJCGZJ2USvhRI8wDwOsl+orYcRm/XmViXe3AAAAA" +
                    "AABAAAAgEv/V+vD2ftLTObetBp5Tgl/PxZLHoNyVsWqmtWKHX4BpBFr6s0V5LQQNDtc+nv4H8L" +
                    "JMGJb8Azqj5p5tSElslOY0x8B1lazvt8dMpSeN2+B+C57qNpmu8b3l/a+pwSDUsRWw1NP6geW5" +
                    "/onN8DpliMidYYhZIYSSoOQF+a+q3LhAAAAAAABAAAAgI+guJ+7hAmx/z5G7Lu05KlkwiHtYlW" +
                    "MURi0W1JntqNwbGyQ6bHBDkwCJh7UBymPkBmZGzRt4+pttjRHWoLOdHsthI42wvkdryKHLE54Z" +
                    "bDaTBdEaBIgDaTjYkpz8BmUgoo7cFI73JuNgSmF1cn09QAhmELRahfaMPnz7hvJ6GADAAAAAAA" +
                    "BAAAAgCzwwlUF1Ah4qTW09Izkhf54G93UvUpOymt3NBjyUyv7TeHM5l3AVbL2TcjdJcxFZ4oxk" +
                    "5uKVrelDlGFLE9SyCEkJoUn88aJ7fVHMOuG4804aL44/ReEudD+fhuhBdpsazJB+7/rhj4etu7" +
                    "78cyc3OKCxEVnvdwUCRmUwX42J6BmAAAAAAABAAAAgJl7NgOXqrYT4/OEdQolwd09MivxI5iVf" +
                    "8hodPkC17fKdenTLXYzGuod+UvK87loAs8/WHpWvxCDB61fnVqVYWqFZ4sPk/sRbBVPNN0YCbY" +
                    "Awj+S8lEV6PxTZCv9nXH7bOTMEVN9PZ7amT3+aTrQWH7Nj32VcrfazXaRjM3Lb/42AAAAAAABA" +
                    "AAAgA5s27V5yxNNXa6IrCskGEEuVYTkIOekb2KkvEi99WCI/W26MBHMnUmdI9uKeBWVFOPy2/T" +
                    "lqn9RL9WNxmlKKEoChDnOhe0fnbgwp5l8v0NC/ZwZEjVDpmk3n46PbVepscNQr+31a+E+XBYij" +
                    "o9ZlpnCg78Rme1NtTpEtSN2mzIPAA=="));
        } catch (IOException e) {
            e.printStackTrace();
        }
        PUBLIC_KEY = pub;
    }

    @BeforeClass
    public static void testSetup() {
        random = new SecureRandom();
    }

    public byte[] getRandomData() {
        byte[] data = new byte[random.nextInt(100) + 20];
        random.nextBytes(data);
        return data;
    }

    // so we dont need to check for exceptions every time we want to decrypt
    private byte[] decrypt(AbePrivateKey privateKey, AbeEncrypted encryptedData) {
        try {
            return Cpabe.decrypt(privateKey, encryptedData);
        } catch (Exception e) {
            return null;
        }
    }

    @Test
    public void addAttributesTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();

        String policy1 = "(att1 and att2) or att3";
        String policy2 = "att3 or att4 >= 5";

        AbeEncrypted policy1EncryptedTest1 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest1 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest2 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest2 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest3 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest3 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest4 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest4 = Cpabe.encrypt(pubKey, policy2, data);
        
        AbeEncrypted policy1EncryptedTest5 = Cpabe.encrypt(pubKey, policy1, data);
        AbeEncrypted policy2EncryptedTest5 = Cpabe.encrypt(pubKey, policy2, data);

        String att1att2Attribute = "att1 att2";
        String att1Attribute = "att1";

        Pair<Element, Integer> preKey1 = Cpabe.preKeygen(smKey);
        Pair<Element, Integer> preKey2 = Cpabe.preKeygen(smKey);

        AbePrivateKey att1att2Key = Cpabe.keygen(smKey, att1att2Attribute, preKey1);
        AbePrivateKey att1Key = Cpabe.keygen(smKey, att1Attribute, preKey2);

        byte[] dec1 = Cpabe.decrypt(att1att2Key, policy1EncryptedTest1);
        assertTrue(Arrays.equals(data, dec1));
        assertFalse(Arrays.equals(data, decrypt(att1att2Key, policy2EncryptedTest1)));
        
        assertFalse(Arrays.equals(data, decrypt(att1Key, policy1EncryptedTest2)));
        assertFalse(Arrays.equals(data, decrypt(att1Key, policy2EncryptedTest2)));


        AbePrivateKey att1att2att3Key = att1att2Key.merge(Cpabe.keygen(smKey, "att3", preKey1));
        AbePrivateKey att1att3Key = att1Key.merge(Cpabe.keygen(smKey, "att3", preKey2));
        AbePrivateKey att1att4Key = att1Key.merge(Cpabe.keygen(smKey, "att4=42", preKey2));

        assertTrue(Arrays.equals(data, decrypt(att1att2att3Key, policy1EncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(att1att2att3Key, policy2EncryptedTest3)));

        assertTrue(Arrays.equals(data, decrypt(att1att3Key, policy1EncryptedTest4)));
        assertTrue(Arrays.equals(data, decrypt(att1att3Key, policy2EncryptedTest4)));

        assertFalse(Arrays.equals(data, decrypt(att1att4Key, policy1EncryptedTest5)));
        assertTrue(Arrays.equals(data, decrypt(att1att4Key, policy2EncryptedTest5)));
    }

    @Test
    public void cipherTextSerializationTest() throws Exception {
        File folder = TestUtil.prepareTestFolder();

        AbeSecretMasterKey msk = Cpabe.setup(2);
        AbePublicKey pub = msk.getPublicKey();

        AbeSecretMasterKey mskClone = AbeSecretMasterKey.readFromByteArray(msk.getAsByteArray());
        AbePublicKey pubClone = AbePublicKey.readFromByteArray(pub.getAsByteArray());

        assertEquals(msk, mskClone);
        assertEquals(pub, pubClone);

        String policy1 = "(att1 and att2) or att3";

        AbeEncrypted enc = Cpabe.encrypt(pub, policy1, getRandomData());
        CipherText cto = enc.getCipher();

        CipherText ctc = CipherText.readFromByteArray(cto.getAsByteArray(pub), pub);

        assertEquals(cto, ctc);

        File ctFile = new File(folder, "ct.dat");

        AbeOutputStream out = new AbeOutputStream(new FileOutputStream(ctFile), pub);
        cto.writeToStream(out);
        out.flush();
        out.close();

        AbeInputStream in = new AbeInputStream(new FileInputStream(ctFile), pub);
        CipherText ctr = CipherText.readFromStream(in);
        in.close();

        assertEquals(cto, ctr);
    }

    @Test
    public void encryptDecryptTestWithFiles() throws Exception {
        File folder = TestUtil.prepareTestFolder();
        File mskFile = new File(folder, "msk.dat");
        File pubFile = new File(folder, "pub.dat");

        Cpabe.setup(pubFile, mskFile);

        AbePublicKey pub = AbePublicKey.readFromFile(pubFile);
        assertNotNull(pub);

        String policy1 = "(att1 and att2) or att3";

        File data1File = TestUtil.randomData();
        File enc1File = new File(folder, "enc1.dat");
        Cpabe.encrypt(pubFile, policy1, data1File, enc1File);

        AbeEncrypted ct = AbeEncrypted.readFromFile(pub, enc1File);
        assertNotNull(ct);

        String att1att2Attribute = "att1 att2";
        String att1Attribute = "att1";

        File private1File = new File(folder, "private1.dat");
        Cpabe.keygenSingle(private1File, mskFile, att1att2Attribute);

        File decrypted1File = new File(folder, "dec1.dat");
        Cpabe.decrypt(private1File, enc1File, decrypted1File);

        assertTrue(Arrays.equals(TestUtil.read(data1File), TestUtil.read(decrypted1File)));

        File secretComponentFile = new File(folder, "usk1.dat");
        Cpabe.preKeygen(mskFile, secretComponentFile);

        File private2File = new File(folder, "private2.dat");
        Cpabe.keygen(private2File, mskFile, att1att2Attribute, secretComponentFile);

        File decrypted2File = new File(folder, "dec2.dat");
        Cpabe.decrypt(private1File, enc1File, decrypted2File);

        assertTrue(Arrays.equals(TestUtil.read(data1File), TestUtil.read(decrypted2File)));
    }

    @Test
    public void setupAndObjectTestWithFiles() throws Exception {
        File folder = TestUtil.prepareTestFolder();
        File mskFile = new File(folder, "msk.dat");
        File pubFile = new File(folder, "pub.dat");

        Cpabe.setup(7, pubFile, mskFile);

        AbeSecretMasterKey msk = AbeSecretMasterKey.readFromFile(mskFile);
        AbeSecretMasterKey msk2 = Cpabe.setup(7);

        assertEquals(msk, msk);
        assertNotEquals(msk, 1);
        assertNotEquals(msk, null);
        assertNotEquals(msk, msk2);

        assertEquals(msk.getPublicKey(), msk.getPublicKey());
        assertNotEquals(msk.getPublicKey(), 1);
        assertNotEquals(msk.getPublicKey(), null);
        assertNotEquals(msk.getPublicKey(), msk2.getPublicKey());
    }

    @Test
    public void encryptDecryptTest() throws Exception {
        LinkedHashMap<String, LinkedHashMap<String, Boolean>> testVectors = new LinkedHashMap<String, LinkedHashMap<String, Boolean>>();

        LinkedHashMap<String, Boolean> vector;

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=5", false);
        vector.put("att1=6", true);
        vector.put("att1=623234", true);
        testVectors.put("att1>5", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=0", true);
        vector.put("att1=1", true);
        vector.put("att1=65336", true);
        vector.put("att1=65337", false);
        vector.put("att1=65338", false);
        vector.put("att1=65339", false);
        testVectors.put("att1<=65336", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=4", false);
        vector.put("att1=5", false);
        vector.put("att1=6", true);
        vector.put("att1=7", true);
        vector.put("att1=8", false);
        vector.put("att1=9", false);
        vector.put("att1=623234", false);
        testVectors.put("att1>5 and att1<8", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1=5 att2=70", false);
        vector.put("att1=5 att2=70 att3", true);
        vector.put("att1=6 att3", true);
        vector.put("att1=6 att2=70", true);
        vector.put("att1=4 att2=80 att3", false);
        testVectors.put("2 of (att1>5, att2<75, att3)", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1", true);
        vector.put("att2", false);
        testVectors.put("att1", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1", false);
        vector.put("att2", false);
        testVectors.put("att1 and att2", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        testVectors.put("(att1 and att2) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att1 att4", false);
        vector.put("att1 att5", false);
        vector.put("att1 att4 att5", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att2 att3 att4 att5", true);
        testVectors.put("(att1 and (att2 or (att4 and att5))) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", false);
        vector.put("att1 att2 att3", true);
        testVectors.put("2 of (att1, att2, att3)", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", false);
        vector.put("att1 att3", false);
        vector.put("att2 att3", false);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att4", true);
        vector.put("att1 att3 att4", true);
        vector.put("att1 att2 att3 att4", true);
        testVectors.put("2 of (att1, (att2 and att3), att4)", vector);

        AbeSecretMasterKey msk = Cpabe.setup(100);
        // System.out.println("PK: " + Base64.toBase64String(msk.getPublicKey().getAsByteArray()));

        for(Map.Entry<String, LinkedHashMap<String, Boolean>> policy : testVectors.entrySet()) {
            System.out.println("Policy: " + policy.getKey());

            byte[] data = getRandomData();
            AbeEncrypted enc = Cpabe.encrypt(msk.getPublicKey(), policy.getKey(), data);
            assertNotNull(enc);

            byte[] encData = enc.writeEncryptedData(msk.getPublicKey());

            for(Map.Entry<String, Boolean> privateKey : policy.getValue().entrySet()) {
                System.out.println("Private key attributes: " + privateKey.getKey());

                AbePrivateKey pk = Cpabe.keygenSingle(msk, privateKey.getKey());
                assertNotNull(pk);

                AbeEncrypted encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
                assertNotNull(encCopy);

                boolean success = false;
                boolean failed = false;
                try {
                    byte[] decData = encCopy.writeDecryptedData(pk);
                    success = Arrays.equals(data, decData);
                } catch (AbeDecryptionException e) {
                    //e.printStackTrace();
                    failed = true;
                }
                System.out.println("should success: " + privateKey.getValue() + " is success: " + success + " has failed: " + failed);
                if (privateKey.getValue()) {
                    assertTrue(success && !failed);
                } else {
                    assertFalse(success && failed);
                }
            }
        }
    }

    @Test
    public void userCeilingTest() {
        HashMap<Integer, Integer> testCases = new HashMap<Integer, Integer>();
        testCases.put(2, 4);
        testCases.put(3, 4);
        testCases.put(4, 9);
        testCases.put(8, 9);
        testCases.put(9, 16);
        testCases.put(15, 16);
        testCases.put(16, 25);
        testCases.put(24, 25);
        testCases.put(25, 36);

        for (Map.Entry<Integer, Integer> testCase : testCases.entrySet()) {
            int usersSqrt = (int)(Math.ceil(Math.sqrt(testCase.getKey()+1)));
            int users = usersSqrt * usersSqrt;
            // System.out.println("in: " + testCase.getKey() + ", out: " + users + ", expected out: " + testCase.getValue());
            assertEquals((Integer)users, testCase.getValue());
        }
    }

    @Test
    public void encryptDecryptRevokedTest() throws Exception {
        LinkedHashMap<String, LinkedHashMap<String, Boolean>> testVectors = new LinkedHashMap<String, LinkedHashMap<String, Boolean>>();

        LinkedHashMap<String, Boolean> vector;

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        testVectors.put("att1 and att2", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        testVectors.put("(att1 and att2) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1 att4 att5", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att2 att3 att4 att5", true);
        testVectors.put("(att1 and (att2 or (att4 and att5))) or att3", vector);

        AbeSecretMasterKey msk = Cpabe.setup(100);

        byte[] data = getRandomData();

        for(Map.Entry<String, LinkedHashMap<String, Boolean>> policy : testVectors.entrySet()) {
            System.out.println("Policy: " + policy.getKey());

            for(Map.Entry<String, Boolean> privateKey : policy.getValue().entrySet()) {
                System.out.println("Private key attributes: " + privateKey.getKey());

                AbePrivateKey privateKeyNonRevoked1 = Cpabe.keygenSingle(msk, privateKey.getKey());
                AbePrivateKey privateKeyRevoked = Cpabe.keygenSingle(msk, privateKey.getKey());
                AbePrivateKey privateKeyNonRevoked2 = Cpabe.keygenSingle(msk, privateKey.getKey());

                AbeEncrypted enc = Cpabe.encrypt(msk.getPublicKey(), policy.getKey(), data,
                        new int[]{ privateKeyRevoked.position.counter });
                assertNotNull(enc);

                byte[] ciphertextCopy = enc.writeEncryptedData(msk.getPublicKey());

                byte[] plaintext = Cpabe.decrypt(privateKeyNonRevoked1, AbeEncrypted.read(ciphertextCopy, msk.getPublicKey()));
                assertNotNull(plaintext);
                assertTrue(Arrays.equals(data, plaintext));

                boolean exceptionThrown = false;
                plaintext = new byte[0];
                try {
                    plaintext = Cpabe.decrypt(privateKeyRevoked, AbeEncrypted.read(ciphertextCopy, msk.getPublicKey()));
                } catch (DecryptionException e) {
                    exceptionThrown = true;
                }
                assertFalse(Arrays.equals(data, plaintext));
                assertTrue(exceptionThrown);

                plaintext = Cpabe.decrypt(privateKeyNonRevoked2, AbeEncrypted.read(ciphertextCopy, msk.getPublicKey()));
                assertNotNull(plaintext);
                assertTrue(Arrays.equals(data, plaintext));
            }
        }
    }

    @Test
    public void encryptDecryptAttributeReuseTest() throws Exception {
        AbeSecretMasterKey msk = Cpabe.setup(2);

        String policy1 = "(att1 and att2) or (att1 and att3)";

        byte[] data = getRandomData();
        AbeEncrypted enc = Cpabe.encrypt(msk.getPublicKey(), policy1, data);
        assertNotNull(enc);

        byte[] encData = enc.writeEncryptedData(msk.getPublicKey());

        String att1att2Attribute = "att1 att2";
        String att1att3Attribute = "att1 att3";
        String att3att2Attribute = "att3 att2";

        AbePrivateKey priv1 = Cpabe.keygenSingle(msk, att1att2Attribute);
        AbePrivateKey priv2 = Cpabe.keygenSingle(msk, att1att3Attribute);
        AbePrivateKey priv3 = Cpabe.keygenSingle(msk, att3att2Attribute);

        AbeEncrypted encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
        byte[] decData = encCopy.writeDecryptedData(priv1);
        assertTrue(Arrays.equals(data, decData));

        encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
        decData = encCopy.writeDecryptedData(priv2);
        assertTrue(Arrays.equals(data, decData));

        boolean exceptionThrown = false;
        try {
            encCopy = AbeEncrypted.read(encData, msk.getPublicKey());
            decData = encCopy.writeDecryptedData(priv3);
        } catch (AbeDecryptionException e) {
            exceptionThrown = true;
        }

        assertTrue(exceptionThrown);
    }

    @Test
    public void privateKeyMergeTest() throws Exception {
        AbeSecretMasterKey msk = Cpabe.setup(2);

        String policy1 = "(att1 and att2) or att3";

        byte[] data = getRandomData();
        AbeEncrypted enc1 = Cpabe.encrypt(msk.getPublicKey(), policy1, data);
        assertNotNull(enc1);

        byte[] encData = enc1.writeEncryptedData(msk.getPublicKey());

        AbeEncrypted enc2 = AbeEncrypted.read(encData, msk.getPublicKey());

        assertNotNull(enc2);

        String att1att2Attribute = "att1 att2";
        String att4Attribute = "att4";

        Pair<Element, Integer> secret = Cpabe.preKeygen(msk);

        AbePrivateKey priv1 = Cpabe.keygen(msk, att1att2Attribute, secret);
        AbePrivateKey priv2 = Cpabe.keygen(msk, att4Attribute, secret);

        assertEquals(2, priv1.getComponents().size());
        assertEquals(1, priv2.getComponents().size());

        AbePrivateKey privMerge = priv1.merge(priv2);

        assertNotNull(privMerge);
        assertEquals(3, privMerge.getComponents().size());

        byte[] dec2Data = enc2.writeDecryptedData(privMerge);

        assertTrue(Arrays.equals(data, dec2Data));

        assertTrue(privMerge.equals(AbePrivateKey.readFromByteArray(privMerge.getAsByteArray())));
    }

    @Test
    public void userIndexTest() {
        AbeUserIndex i1 = new AbeUserIndex(4, 0);
        assertEquals(0, i1.i);
        assertEquals(0, i1.j);
        assertEquals(4, i1.m);

        assertEquals(i1, i1);

        AbeUserIndex i2 = new AbeUserIndex(i1.i, i1.j, i1.m);

        assertEquals(i1, i2);
        assertEquals(0, i2.counter);

        i1 = new AbeUserIndex(4, 9);
        assertEquals(2, i1.i);
        assertEquals(1, i1.j);
        assertEquals(4, i1.m);

        i2 = new AbeUserIndex(i1.i, i1.j, i1.m);

        assertEquals(i1, i2);
        assertEquals(9, i2.counter);

        // negative tests...
        i1 = new AbeUserIndex(4, 0);
        i2 = new AbeUserIndex(5, 0);

        assertNotEquals(i1, i2);
        assertNotEquals(i1, 4);
        assertNotEquals(i1, null);

        i1 = new AbeUserIndex(4, 0);
        i2 = new AbeUserIndex(4, 1);

        assertNotEquals(i1, i2);
    }

    @Test
    public void treeSatisfaction() throws Exception {
        LinkedHashMap<String, LinkedHashMap<String, Boolean>> testVectors = new LinkedHashMap<String, LinkedHashMap<String, Boolean>>();

        LinkedHashMap<String, Boolean> vector;
        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        testVectors.put("(att1 and att2) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att1 att4", false);
        vector.put("att1 att5", false);
        vector.put("att1 att4 att5", true);
        vector.put("att3", true);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att2 att3 att4 att5", true);
        testVectors.put("(att1 and (att2 or (att4 and att5))) or att3", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", true);
        vector.put("att1 att3", true);
        vector.put("att2 att3", true);
        vector.put("att1", false);
        vector.put("att2", false);
        vector.put("att3", false);
        vector.put("att1 att2 att3", true);
        testVectors.put("2 of (att1, att2, att3)", vector);

        vector = new LinkedHashMap<String, Boolean>();
        vector.put("att1 att2", false);
        vector.put("att1 att3", false);
        vector.put("att2 att3", false);
        vector.put("att1 att2 att3", true);
        vector.put("att1 att4", true);
        vector.put("att1 att3 att4", true);
        vector.put("att1 att2 att3 att4", true);
        testVectors.put("2 of (att1, (att2 and att3), att4)", vector);

        for(Map.Entry<String, LinkedHashMap<String, Boolean>> policy : testVectors.entrySet()) {
            System.out.println("Policy: " + policy.getKey());

            for(Map.Entry<String, Boolean> privateKey : policy.getValue().entrySet()) {
                System.out.println("Private key attributes: " + privateKey.getKey());

                Set<String> attributes = new HashSet<String>();
                for(String attr : privateKey.getKey().split(" ")) {
                    attributes.add(attr);
                }

                assertEquals(privateKey.getValue(), Lw14Util.satisfies(policy.getKey(), attributes, PUBLIC_KEY));
            }
        }
    }

    @Test
    public void pascalRowTest() throws Exception {
        long[][] a = new long[][]{
                new long[]{ 1 },
                new long[]{ 1, 1 },
                new long[]{ 1, 2, 1 },
                new long[]{ 1, 3, 3, 1 },
                new long[]{ 1, 4, 6, 4, 1 },
        };
        for(int i = 0; i < a.length; i++) {
            assertTrue(Arrays.equals(a[i], Lw14Util.getPascalRow(i+1)));
        }
    }

    @Test
    public void nextLongPermutationTest() throws Exception {
        long value = 3;
        Long[] expectedResults = new Long[]{
                5L,
                6L,
                9L,
                10L,
                12L,
                17L
        };
        for (Long expectedResult : expectedResults) {
            long result = Lw14Util.getNextLexicographicalPermutation(value);
            assertTrue(expectedResult.equals(result));
            value = result;
        }

        BigInteger bigValue = BigInteger.valueOf(3);
        for (Long expectedResult : expectedResults) {
            BigInteger result = Lw14Util.getNextLexicographicalPermutation(bigValue);
            assertTrue(BigInteger.valueOf(expectedResult).equals(result));
            bigValue = result;
        }
    }

    @Test
    public void powerSetIteratorTest() throws Exception {
        Set<Integer> set = new HashSet<Integer>();
        set.add(2);
        set.add(4);
        set.add(5);

        SortedPowerSetIterator<Integer> iterator = new SortedPowerSetIterator<Integer>(set);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 0);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 1);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 1);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 1);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 2);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 2);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 2);
        assertTrue(iterator.hasNext());
        assertTrue(iterator.next().size() == 3);
        assertFalse(iterator.hasNext());
    }

    @Test
    public void numberTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();

        byte[] data = getRandomData();
        int number = random.nextInt(100) + 20; // 20-119
        String greaterPolicy = "someNumber > " + number;
        String greaterEqPolicy = "someNumber >= " + number;
        String smallerPolicy = "someNumber < " + number;
        String smallerEqPolicy = "someNumber <= " + number;

        // each AbeEncrypted can only be decrypted once, since we advance the stream to after the AES data.
        AbeEncrypted greaterEncryptedTest1 = Cpabe.encrypt(pubKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest1 = Cpabe.encrypt(pubKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest1 = Cpabe.encrypt(pubKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest1 = Cpabe.encrypt(pubKey, smallerEqPolicy, data);
        
        AbeEncrypted greaterEncryptedTest2 = Cpabe.encrypt(pubKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest2 = Cpabe.encrypt(pubKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest2 = Cpabe.encrypt(pubKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest2 = Cpabe.encrypt(pubKey, smallerEqPolicy, data);
        
        AbeEncrypted greaterEncryptedTest3 = Cpabe.encrypt(pubKey, greaterPolicy, data);
        AbeEncrypted greaterEqEncryptedTest3 = Cpabe.encrypt(pubKey, greaterEqPolicy, data);
        AbeEncrypted smallerEncryptedTest3 = Cpabe.encrypt(pubKey, smallerPolicy, data);
        AbeEncrypted smallerEqEncryptedTest3 = Cpabe.encrypt(pubKey, smallerEqPolicy, data);

        String greaterAttribute = "someNumber = " + Integer.toString(number + 1);
        String smallerAttribute = "someNumber = " + Integer.toString(number - 1);
        String equalAttribute = "someNumber = " + Integer.toString(number);

        AbePrivateKey greaterKey = Cpabe.keygenSingle(smKey, greaterAttribute);
        AbePrivateKey smallerKey = Cpabe.keygenSingle(smKey, smallerAttribute);
        AbePrivateKey equalKey = Cpabe.keygenSingle(smKey, equalAttribute);

        // greaterKey
        assertTrue(Arrays.equals(data, decrypt(greaterKey, greaterEncryptedTest1)));
        assertTrue(Arrays.equals(data, decrypt(greaterKey, greaterEqEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, smallerEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(greaterKey, smallerEqEncryptedTest1)));

        // smallerKey
        assertFalse(Arrays.equals(data, decrypt(smallerKey, greaterEncryptedTest2)));
        assertFalse(Arrays.equals(data, decrypt(smallerKey, greaterEqEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, smallerEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(smallerKey, smallerEqEncryptedTest2)));

        // equalKey
        assertFalse(Arrays.equals(data, decrypt(equalKey, greaterEncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(equalKey, greaterEqEncryptedTest3)));
        assertFalse(Arrays.equals(data, decrypt(equalKey, smallerEncryptedTest3)));
        assertTrue(Arrays.equals(data, decrypt(equalKey, smallerEqEncryptedTest3)));
    }

    @Test
    public void coordinateTest() throws Exception {
        AbeSecretMasterKey smKey = Cpabe.setup();
        AbePublicKey pubKey = smKey.getPublicKey();
        byte[] data = getRandomData();

        double latitudeBerlin = 52.51217;
        double longitudeBerlin = 13.42106;

        double latitudeHamburg = 53.55108;
        double longitudeHamburg = 9.99368;

        double latitudeSchwerin = 53.63550;
        double longitudeSchwerin = 11.40125;

        String policyBerlin = String.format("a:%f:%f:22:1", latitudeBerlin, longitudeBerlin);
        String policyHamburg = String.format("a:%f:%f:24:1", latitudeHamburg, longitudeHamburg);

        AbeEncrypted berlinEncryptedTest1 = Cpabe.encrypt(pubKey, policyBerlin, data);
        AbeEncrypted hamburgEncryptedTest1 = Cpabe.encrypt(pubKey, policyHamburg, data);
        
        AbeEncrypted berlinEncryptedTest2 = Cpabe.encrypt(pubKey, policyBerlin, data);
        AbeEncrypted hamburgEncryptedTest2 = Cpabe.encrypt(pubKey, policyHamburg, data);
        
        AbeEncrypted berlinEncryptedTest3 = Cpabe.encrypt(pubKey, policyBerlin, data);
        AbeEncrypted hamburgEncryptedTest3 = Cpabe.encrypt(pubKey, policyHamburg, data);

        String berlinAttribute = String.format("a:%f:%f", latitudeBerlin, longitudeBerlin);
        String hamburgAttribute = String.format("a:%f:%f", latitudeHamburg, longitudeHamburg);
        String schwerinAttribute = String.format("a:%f:%f", latitudeSchwerin, longitudeSchwerin);

        AbePrivateKey berlinKey = Cpabe.keygenSingle(smKey, berlinAttribute);
        AbePrivateKey hamburgKey = Cpabe.keygenSingle(smKey, hamburgAttribute);
        AbePrivateKey schwerinKey = Cpabe.keygenSingle(smKey, schwerinAttribute);

        // berlinKey
        assertTrue(Arrays.equals(data, decrypt(berlinKey, berlinEncryptedTest1)));
        assertFalse(Arrays.equals(data, decrypt(berlinKey, hamburgEncryptedTest1)));

        // hamburgKey
        assertFalse(Arrays.equals(data, decrypt(hamburgKey, berlinEncryptedTest2)));
        assertTrue(Arrays.equals(data, decrypt(hamburgKey, hamburgEncryptedTest2)));
        

        // schwerinKey
        assertFalse(Arrays.equals(data, decrypt(schwerinKey, berlinEncryptedTest3)));
        assertFalse(Arrays.equals(data, decrypt(schwerinKey, hamburgEncryptedTest3)));
    }
}
