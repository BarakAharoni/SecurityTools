import argparse
from PIL import Image
from PIL.ExifTags import TAGS

def extract_exif_info(image_path):
    try:
        img = Image.open(image_path)
        img_exif = img.getexif()
        if img_exif:
            img_exif_dict = dict(img_exif)
            for key, val in img_exif_dict.items():
                if key in TAGS:
                    print(f"{TAGS[key]} - {val}")
        else:
            print("Sorry, image has no exif data.")
    except FileNotFoundError:
        print("File not found. Please provide a valid image path.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract EXIF metadata from an image.")
    parser.add_argument("image_path", type=str, help="Path to the image file")
    args = parser.parse_args()
    extract_exif_info(args.image_path)
