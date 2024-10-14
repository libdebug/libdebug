import os

folder_to_scrape = "../libdebug"

out_folder = "./from_pydoc/generated"

if os.path.exists(out_folder):
    os.system(f"rm -rf {out_folder}")

def create_if_not_exists(folder):
    if not os.path.exists(folder):
        os.makedirs(folder)

def md_rename(file):
    return file.replace(".py", ".md")

for root, dirs, files in os.walk(folder_to_scrape):
    for file in files:
        # Skip init files and such
        if file.startswith("_"):
            continue

        # Only scrape .py, .c, and .h files
        if file.endswith(".py"):
            file_path = os.path.join(root, file)
            print(f"File path: {file_path}")

            # File path relative to libdebug/libdebug
            file_path = file_path.replace(folder_to_scrape + "/", "")
            print(f"Scraping {file_path}")

            if "/" in file_path:
                folder_to_create = os.path.join(out_folder, file_path[:file_path.rfind("/")])
            else:
                folder_to_create = out_folder

            create_if_not_exists(folder_to_create)
            print(f"Creating folder {folder_to_create}")

            new_file_path = os.path.join(folder_to_create, md_rename(file))
            print(f"Creating {new_file_path}")

            # Write the file, including a yml header to avoid search priority problems
            with open(new_file_path, "w") as f:
                module_name = "libdebug." + file_path.split(".")[0].replace("/", ".")

                what_to_write = f"---\ntitle: {module_name}\nboost: 0.5\n---\n# {module_name}\n::: {module_name}\n"

                f.write(what_to_write)