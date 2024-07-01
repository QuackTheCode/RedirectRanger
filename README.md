# RedirectRanger

RedirectRanger is a tool designed to check the redirection of URLs from HTTP to HTTPS. It extracts URLs from a specified file, performs cURL requests to check redirection, and logs the results. It should ideally be used in combination with URLs mapped or found from various other tools such as Burp Suite, GAP, Katana or any other tool alongside the results from manually mapping the application and navigating through everything. 

Its main use is to test if the website redirects all HTTP requests to HTTPS endpoints instead across all functionality.

Currently, the tool only works with the output of the extracted URLs from the GAP Plugin in Burp Suite - a specific format. There are plans to change this to work with any format/list of URLs.

## Features

- Extract URLs from a text file.
- Filter out for unique URLs (removes duplicates)
- Check if URLs are redirected from HTTP to HTTPS.
- Log results into separate files based on the type of response.
- Automatically creates a directory based on the domain of the first URL.
- Only creates result files if there are entries.

## Usage

1. Clone the repository:
   
   ```bash
   git clone https://github.com/QuackTheCode/RedirectRanger.git
   cd RedirectRanger

2. Prepare a text file with HTTPs URLs (in this case, extracted from the GAP tool)

   ```bash
   ../../test/test [http://site.com/redirect_to_https]
   ../../test2/test [http://site.com/no_redirect]
   ../../test3/test [http://site.com/other_response]
   ```

   ![Demo of RedirectRanger](https://github.com/QuackTheCode/RedirectRanger/blob/main/demo/urlstxt.png)

3. Run the tool

   ```bash
   python RedirectRanger.py -l urls.txt
   ```

   ![Demo of RedirectRanger](https://github.com/QuackTheCode/RedirectRanger/blob/main/demo/demo2.gif)

## Output

   ```sql
      example.com/
         ├── curl_commands.txt
         ├── results.txt
         ├── successful_redirects.txt (only if there are successful redirects)
         ├── no_redirects.txt (only if there are URLs that did not redirect)
         └── other_responses.txt (only if there are other types of responses)
   ```

   ![Demo of RedirectRanger](https://github.com/QuackTheCode/RedirectRanger/blob/main/demo/demo3.png)
