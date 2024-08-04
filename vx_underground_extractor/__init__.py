#!/usr/bin/env python3

import cart
import json
import os
from datetime import datetime
import subprocess

import luigi
from luigi import Task, LocalTarget, Parameter, PathParameter

from pathlib import Path

from typing import Generator, Optional, List

import py7zr
#import binaryninja

from multiprocessing import Pool

import logging
import rich
import rich.logging

logger = logging.getLogger(__name__)

class Extractor(Task):
    vx_path = PathParameter(exists=True)
    """ The path to the VX-Underground archive."""
    extracted_base_path = PathParameter()
    """ The path to extract samples to."""
    sample_path = PathParameter()
    """ The path to the sample file."""
    family_name = Parameter()
    """ The name of the malware family."""

    @property
    def output_path(self) -> Path:
        return Path(self.output().path)

    @property
    def input_file(self) -> Path:
        return Path(self.input().path)

    def input(self):
        assert str(self.sample_path)[0] != "/", "Sample path must be relative."
        return LocalTarget(self.vx_path / "Families" / self.family_name / self.sample_path.with_suffix(".7z"))

    def output(self):
        return LocalTarget(self.extracted_base_path / "extracted" / self.family_name / self.sample_path)

    def run(self):
        logger.info(f"Extracting {self.sample_path} from {self.family_name} to {self.output_path}")
        password = "infected" # Please don't ask VX-Underground for the password.
        with py7zr.SevenZipFile(self.input_file, 'r', password=password) as archive:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            archive.extract(path=self.output_path.parent, targets=[self.output_path.name])
            self.output_path.chmod(0o666) # For extra protection, no execute

class MakeCart(Task):
    vx_path = PathParameter(exists=True)
    """ The path to the VX-Underground archive."""
    extracted_base_path = PathParameter()
    """ The path to extract samples to."""
    family_name = Parameter()
    """ The name of the malware family."""
    sample_path = PathParameter()
    """ The path to the sample file."""

    @property
    def output_path(self) -> Path:
        return Path(self.output().path)

    @property
    def input_file(self) -> Path:
        return Path(self.input().path)

    def requires(self):
        return Extractor(vx_path=self.vx_path, extracted_base_path=self.extracted_base_path, sample_path=self.sample_path, family_name=self.family_name)

    def input(self):
        return LocalTarget(self.extracted_base_path / "extracted" / self.family_name / self.sample_path)

    def output(self):
        return LocalTarget(self.extracted_base_path / "carts" / self.family_name / self.sample_path.with_suffix(".cart"))

    def run(self):
        logger.info(f"Making CART for {self.family_name} from {self.input_file}")
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        cart.pack_file(
            self.input_file,
            self.output_path,
            optional_header={
                "source": "VX-Underground",
                "family": self.family_name,
                "sample_path": str(self.sample_path.with_suffix(".7z")),
                "source_url": f"https://samples.vx-underground.org/Samples/Families/{self.family_name}/{self.sample_path}.7z",
                "date":  datetime.fromtimestamp(os.path.getmtime(self.input_file)).isoformat(),
            }
        )

# TODO: Ghidra for each family
# TODO: BSim for each Ghidra

# ./analyzeHeadless ~/ghidra_projects Bashlite -recursive -commit "Auto analysis" -process
# ./bsim generatesigs ghidra:///Users/kaida/ghidra_projects/Bashlite --bsim file:///Users/kaida/samples/Bashlite

class GhidraAnalysis(Task):
    vx_path = PathParameter(exists=True)
    """ The path to the VX-Underground archive."""
    extracted_base_path = PathParameter()
    """ The path to extract samples to."""
    family_name = Parameter()
    """ The name of the malware family."""
    ghidra_install_directory = PathParameter(exists=True)
    """The path to the Ghidra install directory"""

    @property
    def project_location(self) -> Path:
        return self.extracted_base_path / "ghidra_projects"

    @property
    def sample_path(self) -> Path:
        return self.extracted_base_path / "carts" / self.family_name

    def input(self):
        return LocalTarget(self.sample_path)

    def output(self):
        # The output is a .gpr Ghidra project file
        return LocalTarget(self.project_location / f"{self.family_name}.gpr")

    def run(self):
        self.project_location.mkdir(parents=True, exist_ok=True)
        command = [
            Path(self.ghidra_install_directory, "support", "analyzeHeadless"),
            self.project_location,
            self.family_name,
            "-recursive", "5",
            "-commit",
            "Auto analysis",
            "-scriptPath",
            Path(__file__).parent,
            "-preScript",
            "set_metadata.py",
            "-import",
            self.sample_path,
        ]

        #metadata = cart.get_metadata_only(self.sample_path)
        environment = {
            "VX_FAMILY": self.family_name,
        }

        print(f"Running Ghidra on {self.sample_path}")
        subprocess.check_call(command, env=environment)

class VXUndergroundArchive():
    vx_path: Path
    extracted_base_path: Path
    ghidra_install_directory: Path

    def __init__(self, vx_path: Path, extracted_base_path: Path, ghidra_install_directory: Optional[Path] = None):
        self.vx_path = vx_path
        self.extracted_base_path = extracted_base_path
        self.ghidra_install_directory = ghidra_install_directory
        if not self.ghidra_install_directory:
            env_var = os.getenv("GHIDRA_INSTALL_DIR")
            if env_var:
                self.ghidra_install_directory = Path(env_var)
            else:
                raise ValueError("Ghidra install directory must be provided.")

    def relative_archive_path(self, path: Path, family: Optional[str] = None) -> Path:
        if family:
            return path.relative_to(self.vx_path / "Families" / family)
        else:
            return path.relative_to(self.vx_path)

    @property
    def family_path(self) -> Path:
        return self.vx_path / "Families"

    @property
    def families(self) -> List[str]:
        return [f.name for f in self.family_path.iterdir() if f.is_dir()]

    def samples(self, family: Optional[str] = None) -> List[Path]:
        sample_list: List[Path] = []
        if family is None:
            sample_list.extend(self.family_path.glob("**/*.7z"))
        else:
            sample_list.extend((self.family_path / family).glob("**/*.7z"))
        return [self.relative_archive_path(path, family).with_suffix("") for path in sample_list]

    def extract_sample_task(self, family: str, sample: str | Path) -> Extractor:
        #logger.info(f"Extracting {sample} from {family}")
        return Extractor(vx_path=self.vx_path, extracted_base_path=self.extracted_base_path, sample_path=sample, family_name=family)

    def extract_family_task(self, family: str) -> List[Extractor]:
        return [self.extract_sample_task(family, sample) for sample in self.samples(family)]

    def extract_all_task(self) -> List[Extractor]:
        tasks: List[Extractor] = []
        for family in self.families:
            for task in self.extract_family_task(family):
                tasks.append(task)
        return tasks

    def make_cart_task(self, family: str, sample: str | Path) -> MakeCart:
        return MakeCart(vx_path=self.vx_path, extracted_base_path=self.extracted_base_path, family_name=family, sample_path=sample)

    def make_cart_family_task(self, family: str) -> List[MakeCart]:
        return [self.make_cart_task(family, sample) for sample in self.samples(family)]

    def make_cart_all_task(self) -> List[MakeCart]:
        tasks: List[MakeCart] = []
        for family in self.families:
            for task in self.make_cart_family_task(family):
                tasks.append(task)
        return tasks

    def analyze_family_task(self, family: str) -> GhidraAnalysis:
        return GhidraAnalysis(vx_path=self.vx_path, extracted_base_path=self.extracted_base_path, family_name=family, ghidra_install_directory=self.ghidra_install_directory)

    def analyze_all_task(self) -> List[GhidraAnalysis]:
        return [self.analyze_family_task(family) for family in self.families]

    def extract_all(self, workers: int = 3):
        #logger.info(f"Extracting all samples from {self.vx_path} to {self.extracted_base_path}")
        with Pool(workers) as pool:
            pool.map(luigi.build, [[x] for x in self.make_cart_all_task()])
            pool.close()
            pool.join()

    def analyse_all(self, workers: int = 3):
        #logger.info(f"Analyzing all samples from {self.vx_path} to {self.extracted_base_path}")
        with Pool(workers) as pool:
            pool.map(luigi.build, [[x] for x in self.analyze_all_task()])
            pool.close()
            pool.join()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract samples from VX-Underground archive.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--ghidra-install-directory", required=False, type=Path, help="The path to the Ghidra install directory.")
    parser.add_argument("VX_ARCHIVE", type=Path, help="The path to the VX-Underground archive.")
    parser.add_argument("EXTRACTED_BASE_PATH", type=Path, help="The path to extract the archive to.")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO, handlers=[rich.logging.RichHandler()])

    vx_archive = VXUndergroundArchive(args.VX_ARCHIVE, args.EXTRACTED_BASE_PATH, args.ghidra_install_directory)
    vx_archive.extract_all()
    vx_archive.analyse_all()

if __name__ == '__main__':
    main()