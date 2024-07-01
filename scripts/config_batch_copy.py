import shutil
import os

def copy_file(src, dst):
    try:
        shutil.copy(src, dst)
        print(f"Copied {src} to {dst}")
    except IOError as e:
        print(f"Unable to copy file. {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def batch_copy(src_template, dst_template, indices):
    for index in indices:
        src = src_template.replace("{index}", str(index))
        dst = dst_template.replace("{index}", str(index))
        
        # Ensure the destination directory exists
        
        copy_file(src, dst)

if __name__ == "__main__":
    CVE_XXX = "CVE-2023-24826"
    src_template = f"/home/n0vic3/fuzzers/fuzzware-experiments/03-fuzzing-new-targets/contiki-ng/rebuilt/{CVE_XXX}/config.yml"
    dst_template = f"/home/n0vic3/fuzzers/fuzzware/examples/month6_original/{CVE_XXX}_{{index}}/config.yml"
    
    # Define the range of indices you want to copy to
    indices = [0, 1, 2]  # You can modify this list as needed

    batch_copy(src_template, dst_template, indices)
